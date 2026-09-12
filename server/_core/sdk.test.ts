import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Request } from "express";

// The sdk module captures environment variables at import time (ENV is a
// snapshot of process.env), so each test sets env before a fresh import.
const dbMocks = vi.hoisted(() => ({
  upsertUser: vi.fn(),
  getUserByOpenId: vi.fn(),
  // BUG-007 gate: authenticateRequest resolves the linked SAMPRAAN identity
  // status on every request. Default to "no linked identity" (platform user
  // without a SAMPRAAN binding); tests that care override it.
  getIdentityByLinkedUserId: vi.fn(),
  // QA #5 gate: server-side session revocation classification. Default to
  // UNTRACKED so legacy token flows are unaffected; revocation tests
  // override it.
  classifyPlatformSession: vi.fn(),
}));

vi.mock("../db", () => dbMocks);

// axios default export is used via axios.create(...); replace the created
// client with one controllable per test.
const postMock = vi.hoisted(() => vi.fn());
vi.mock("axios", () => ({
  default: {
    create: vi.fn(() => ({ post: postMock })),
  },
}));

const ENV_KEYS = {
  jwtSecret: "JWT_SECRET",
  appId: "VITE_APP_ID",
  oAuthServerUrl: "OAUTH_SERVER_URL",
} as const;

const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const key of Object.values(ENV_KEYS)) {
    savedEnv[key] = process.env[key];
  }
  process.env[ENV_KEYS.jwtSecret] = "test-session-secret-value-0123456789";
  process.env[ENV_KEYS.appId] = "sampraan-test-app";
  process.env[ENV_KEYS.oAuthServerUrl] = "https://oauth.example.com";
  vi.clearAllMocks();
  // BUG-007 default: no linked SAMPRAAN identity for the test user — the
  // session gate must pass when no identity binding exists.
  dbMocks.getIdentityByLinkedUserId.mockResolvedValue(undefined);
  // QA #5 default: token not tracked server-side — JWT verification alone
  // governs (legacy/cron token flows).
  dbMocks.classifyPlatformSession.mockResolvedValue({ state: "UNTRACKED" });
});

afterEach(() => {
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  vi.resetModules();
});

async function loadSdk() {
  const mod = await import("./sdk");
  return mod;
}

function expressRequest(headers: Record<string, string | undefined>): Request {
  return {
    headers,
    protocol: "https",
  } as unknown as Request;
}

function signedInUser(overrides: Record<string, unknown> = {}) {
  return {
    id: 1,
    openId: "user-open-id",
    name: "Aarav Mehta",
    email: "aarav@example.com",
    loginMethod: "local",
    role: "user",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
    ...overrides,
  };
}

describe("SDKServer session tokens", () => {
  it("creates and verifies a session token round-trip", async () => {
    const { sdk } = await loadSdk();
    const token = await sdk.createSessionToken("user-open-id", {
      name: "Aarav Mehta",
    });

    const session = await sdk.verifySession(token);
    expect(session).toEqual({
      openId: "user-open-id",
      appId: "sampraan-test-app",
      name: "Aarav Mehta",
    });
  });

  it("rejects an empty or missing session cookie value", async () => {
    const { sdk } = await loadSdk();
    await expect(sdk.verifySession(undefined)).resolves.toBeNull();
    await expect(sdk.verifySession(null)).resolves.toBeNull();
    await expect(sdk.verifySession("")).resolves.toBeNull();
  });

  it("rejects a tampered session token", async () => {
    const { sdk } = await loadSdk();
    const token = await sdk.createSessionToken("user-open-id");
    const tampered = `${token.slice(0, -4)}aaaa`;
    await expect(sdk.verifySession(tampered)).resolves.toBeNull();
  });

  it("rejects a token signed with a different secret", async () => {
    const { sdk } = await loadSdk();
    const token = await sdk.createSessionToken("user-open-id");

    process.env[ENV_KEYS.jwtSecret] = "another-secret-entirely-different";
    vi.resetModules();
    const other = await loadSdk();
    await expect(other.sdk.verifySession(token)).resolves.toBeNull();
  });

  it("honours an expiry in the past", async () => {
    const { sdk } = await loadSdk();
    const token = await sdk.createSessionToken("user-open-id", {
      expiresInMs: -1000, // already expired
    });
    await expect(sdk.verifySession(token)).resolves.toBeNull();
  });

  it("rejects a non-JWT garbage string", async () => {
    const { sdk } = await loadSdk();
    await expect(sdk.verifySession("garbage.token.value")).resolves.toBeNull();
  });

  it("rejects a session payload missing required fields", async () => {
    // A payload that omits a required claim (appId) must never verify.
    // (name: "" alone is valid — nameless users are tolerated.)
    const { sdk } = await loadSdk();
    const token = await sdk.signSession({
      openId: "user-open-id",
      appId: "",
      name: "Aarav Mehta",
    });
    await expect(sdk.verifySession(token)).resolves.toBeNull();
  });

  it("rejects a session bound to a foreign appId", async () => {
    // The verifier binds sessions to the deployment appId: a token minted
    // for another app must not verify here even with a valid signature.
    const { sdk } = await loadSdk();
    const token = await sdk.signSession({
      openId: "user-open-id",
      appId: "some-other-app-id",
      name: "Aarav Mehta",
    });
    await expect(sdk.verifySession(token)).resolves.toBeNull();
  });
});

describe("SDKServer.authenticateRequest", () => {
  it("BUG-007: rejects a session whose linked SAMPRAAN identity is REVOKED", async () => {
    const { sdk } = await loadSdk();
    const { COOKIE_NAME } = await import("../../shared/const");
    const token = await sdk.createSessionToken("user-open-id", {
      name: "Aarav Mehta",
    });
    dbMocks.getUserByOpenId.mockResolvedValue(signedInUser());
    dbMocks.upsertUser.mockResolvedValue(undefined);
    dbMocks.getIdentityByLinkedUserId.mockResolvedValue({
      id: "identity-1",
      linkedUserId: 1,
      status: "REVOKED",
    });

    await expect(
      sdk.authenticateRequest(expressRequest({ cookie: `${COOKIE_NAME}=${token}` }))
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it("BUG-007: rejects a session whose linked SAMPRAAN identity is SUSPENDED", async () => {
    const { sdk } = await loadSdk();
    const { COOKIE_NAME } = await import("../../shared/const");
    const token = await sdk.createSessionToken("user-open-id", {
      name: "Aarav Mehta",
    });
    dbMocks.getUserByOpenId.mockResolvedValue(signedInUser());
    dbMocks.upsertUser.mockResolvedValue(undefined);
    dbMocks.getIdentityByLinkedUserId.mockResolvedValue({
      id: "identity-1",
      linkedUserId: 1,
      status: "SUSPENDED",
    });

    await expect(
      sdk.authenticateRequest(expressRequest({ cookie: `${COOKIE_NAME}=${token}` }))
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it("BUG-007: allows a session whose linked SAMPRAAN identity is ACTIVE", async () => {
    const { sdk } = await loadSdk();
    const { COOKIE_NAME } = await import("../../shared/const");
    const token = await sdk.createSessionToken("user-open-id", {
      name: "Aarav Mehta",
    });
    dbMocks.getUserByOpenId.mockResolvedValue(signedInUser());
    dbMocks.upsertUser.mockResolvedValue(undefined);
    dbMocks.getIdentityByLinkedUserId.mockResolvedValue({
      id: "identity-1",
      linkedUserId: 1,
      status: "ACTIVE",
    });

    const user = await sdk.authenticateRequest(
      expressRequest({ cookie: `${COOKIE_NAME}=${token}` })
    );
    expect(user).toMatchObject({ openId: "user-open-id", role: "user" });
  });

  it("QA #5: rejects a session revoked server-side even though the JWT is still valid", async () => {
    const { sdk } = await loadSdk();
    const { COOKIE_NAME } = await import("../../shared/const");
    const token = await sdk.createSessionToken("user-open-id", {
      name: "Aarav Mehta",
    });
    dbMocks.getUserByOpenId.mockResolvedValue(signedInUser());
    dbMocks.upsertUser.mockResolvedValue(undefined);
    dbMocks.classifyPlatformSession.mockResolvedValue({ state: "REVOKED" });

    await expect(
      sdk.authenticateRequest(expressRequest({ cookie: `${COOKIE_NAME}=${token}` }))
    ).rejects.toMatchObject({ statusCode: 403 });
    expect(dbMocks.classifyPlatformSession).toHaveBeenCalledWith(token);
  });

  it("QA #5: rejects a session expired server-side even though the JWT is still valid", async () => {
    const { sdk } = await loadSdk();
    const { COOKIE_NAME } = await import("../../shared/const");
    const token = await sdk.createSessionToken("user-open-id", {
      name: "Aarav Mehta",
    });
    dbMocks.getUserByOpenId.mockResolvedValue(signedInUser());
    dbMocks.upsertUser.mockResolvedValue(undefined);
    dbMocks.classifyPlatformSession.mockResolvedValue({ state: "EXPIRED" });

    await expect(
      sdk.authenticateRequest(expressRequest({ cookie: `${COOKIE_NAME}=${token}` }))
    ).rejects.toMatchObject({ statusCode: 403 });
  });

  it("QA #5: passes an ACTIVE tracked session", async () => {
    const { sdk } = await loadSdk();
    const { COOKIE_NAME } = await import("../../shared/const");
    const token = await sdk.createSessionToken("user-open-id", {
      name: "Aarav Mehta",
    });
    dbMocks.getUserByOpenId.mockResolvedValue(signedInUser());
    dbMocks.upsertUser.mockResolvedValue(undefined);
    dbMocks.classifyPlatformSession.mockResolvedValue({
      state: "ACTIVE",
      id: "session-row",
      identityId: "identity-1",
      expiresAt: new Date(Date.now() + 3600_000),
    });

    const user = await sdk.authenticateRequest(
      expressRequest({ cookie: `${COOKIE_NAME}=${token}` })
    );
    expect(user).toMatchObject({ openId: "user-open-id" });
  });

  it("authenticates a request with a valid session cookie", async () => {
    const { sdk } = await loadSdk();
    const { COOKIE_NAME } = await import("../../shared/const");
    const token = await sdk.createSessionToken("user-open-id", {
      name: "Aarav Mehta",
    });
    dbMocks.getUserByOpenId.mockResolvedValue(signedInUser());
    dbMocks.upsertUser.mockResolvedValue(undefined);

    const user = await sdk.authenticateRequest(
      expressRequest({ cookie: `${COOKIE_NAME}=${token}` })
    );

    expect(user).toMatchObject({ openId: "user-open-id", role: "user" });
    // lastSignedIn is refreshed on each authenticated request.
    expect(dbMocks.upsertUser).toHaveBeenCalledWith(
      expect.objectContaining({ openId: "user-open-id" })
    );
  });

  it("falls back to the Authorization: Bearer header when no cookie exists", async () => {
    const { sdk } = await loadSdk();
    const token = await sdk.createSessionToken("user-open-id", {
      name: "Aarav Mehta",
    });
    dbMocks.getUserByOpenId.mockResolvedValue(signedInUser());
    dbMocks.upsertUser.mockResolvedValue(undefined);

    const user = await sdk.authenticateRequest(
      expressRequest({ authorization: `Bearer ${token}` })
    );

    expect(user).toMatchObject({ openId: "user-open-id" });
  });

  it("prefers the session cookie over the Authorization header", async () => {
    const { sdk } = await loadSdk();
    const { COOKIE_NAME } = await import("../../shared/const");
    const cookieToken = await sdk.createSessionToken("cookie-user", {
      name: "Cookie User",
    });
    const bearerToken = await sdk.createSessionToken("bearer-user", {
      name: "Bearer User",
    });
    dbMocks.getUserByOpenId.mockImplementation(async (openId: string) =>
      signedInUser({ openId })
    );
    dbMocks.upsertUser.mockResolvedValue(undefined);

    const user = await sdk.authenticateRequest(
      expressRequest({
        cookie: `${COOKIE_NAME}=${cookieToken}`,
        authorization: `Bearer ${bearerToken}`,
      })
    );

    expect(user).toMatchObject({ openId: "cookie-user" });
  });

  it("throws Forbidden when no session is present at all", async () => {
    const { sdk } = await loadSdk();
    await expect(sdk.authenticateRequest(expressRequest({}))).rejects.toThrow(
      "Invalid session cookie"
    );
  });

  it("throws Forbidden when the session token is invalid", async () => {
    const { sdk } = await loadSdk();
    const { COOKIE_NAME } = await import("../../shared/const");
    await expect(
      sdk.authenticateRequest(
        expressRequest({ cookie: `${COOKIE_NAME}=not-a-jwt` })
      )
    ).rejects.toThrow("Invalid session cookie");
  });

  it("syncs an unknown user from the OAuth server on first login", async () => {
    const { sdk } = await loadSdk();
    const { COOKIE_NAME } = await import("../../shared/const");
    const token = await sdk.createSessionToken("new-user-open-id", {
      name: "New User",
    });

    // First lookup: no user yet. After the OAuth sync the user exists.
    dbMocks.getUserByOpenId
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce(signedInUser({ openId: "new-user-open-id" }));
    dbMocks.upsertUser.mockResolvedValue(undefined);
    postMock.mockResolvedValue({
      data: { openId: "new-user-open-id", name: "New User" },
    });

    const user = await sdk.authenticateRequest(
      expressRequest({ cookie: `${COOKIE_NAME}=${token}` })
    );

    expect(user).toMatchObject({ openId: "new-user-open-id" });
    expect(dbMocks.upsertUser).toHaveBeenCalledWith(
      expect.objectContaining({ openId: "new-user-open-id", name: "New User" })
    );
    expect(postMock).toHaveBeenCalledWith(
      expect.stringContaining("GetUserInfoWithJwt"),
      expect.objectContaining({
        projectId: "sampraan-test-app",
        jwtToken: token,
      })
    );
  });

  it("throws Forbidden when the OAuth sync fails for an unknown user", async () => {
    const { sdk } = await loadSdk();
    const { COOKIE_NAME } = await import("../../shared/const");
    const token = await sdk.createSessionToken("ghost-user", {
      name: "Ghost User",
    });
    dbMocks.getUserByOpenId.mockResolvedValue(undefined);
    postMock.mockRejectedValue(new Error("oauth server down"));

    await expect(
      sdk.authenticateRequest(
        expressRequest({ cookie: `${COOKIE_NAME}=${token}` })
      )
    ).rejects.toThrow("Failed to sync user info");
  });

  it("throws Forbidden when the synced user still cannot be found", async () => {
    const { sdk } = await loadSdk();
    const { COOKIE_NAME } = await import("../../shared/const");
    const token = await sdk.createSessionToken("vanishing-user", {
      name: "Vanishing User",
    });
    dbMocks.getUserByOpenId.mockResolvedValue(undefined);
    postMock.mockResolvedValue({
      data: { openId: "vanishing-user", name: "Vanishing User" },
    });

    await expect(
      sdk.authenticateRequest(
        expressRequest({ cookie: `${COOKIE_NAME}=${token}` })
      )
    ).rejects.toThrow("User not found");
  });

  it("builds a cron user with isCron and taskUid", async () => {
    const { sdk } = await loadSdk();
    const { COOKIE_NAME } = await import("../../shared/const");
    const token = await sdk.createSessionToken("cron_task-123", {
      name: "Cron",
    });
    postMock.mockResolvedValue({
      data: {
        openId: "cron_task-123",
        name: "Scheduled",
        taskUid: "task-uid-1",
      },
    });

    const user = await sdk.authenticateRequest(
      expressRequest({ cookie: `${COOKIE_NAME}=${token}` })
    );

    expect(user).toMatchObject({
      openId: "cron_task-123",
      isCron: true,
      taskUid: "task-uid-1",
      role: "user",
    });
  });

  it("throws Forbidden when a cron session is missing taskUid", async () => {
    const { sdk } = await loadSdk();
    const { COOKIE_NAME } = await import("../../shared/const");
    const token = await sdk.createSessionToken("cron_task-456", {
      name: "Cron",
    });
    postMock.mockResolvedValue({
      data: { openId: "cron_task-456", name: "Scheduled", taskUid: null },
    });

    await expect(
      sdk.authenticateRequest(
        expressRequest({ cookie: `${COOKIE_NAME}=${token}` })
      )
    ).rejects.toThrow("Cron session missing task_uid");
  });
});

describe("SDKServer.getUserInfo derives loginMethod", () => {
  it.each([
    [
      "google from platforms",
      { platforms: ["REGISTERED_PLATFORM_GOOGLE"] },
      "google",
    ],
    [
      "email from platforms",
      { platforms: ["REGISTERED_PLATFORM_EMAIL"] },
      "email",
    ],
    [
      "microsoft from platforms",
      { platforms: ["REGISTERED_PLATFORM_MICROSOFT"] },
      "microsoft",
    ],
    [
      "github from platforms",
      { platforms: ["REGISTERED_PLATFORM_GITHUB"] },
      "github",
    ],
    [
      "apple from platforms",
      { platforms: ["REGISTERED_PLATFORM_APPLE"] },
      "apple",
    ],
    ["fallback platform field", { platform: "google" }, "google"],
    ["null when nothing is known", {}, null],
  ])("derives %s", async (_label, userInfo, expected) => {
    const { sdk } = await loadSdk();
    postMock.mockResolvedValue({ data: { openId: "user-1", ...userInfo } });

    const result = await sdk.getUserInfo("token");

    expect(result.loginMethod).toBe(expected);
  });
});
