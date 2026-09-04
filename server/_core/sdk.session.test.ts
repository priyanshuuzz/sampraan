import { beforeEach, describe, expect, it, vi } from "vitest";
import { SignJWT, jwtVerify } from "jose";

/**
 * Session verification regression tests (union of two suites).
 *
 * Suite A (actor/session handling): createSessionToken signs `name: ""` when a
 * user has no display name; the verifier must still accept that session.
 * openId and appId remain mandatory. ENV snapshots process.env at module
 * load, so the mock module supplies the secret.
 *
 * Suite B (app binding, security agent): verifySession must reject tokens
 * minted for a different appId even when the signing secret is shared, reject
 * foreign-secret tokens, tolerate empty informational `name`, and fail
 * closed on garbage instead of throwing.
 *
 * Sessions are HS256-signed with ENV.cookieSecret and bound to ENV.appId.
 */

const SECRET = "test-secret-for-vitest-only-0123456789abcdef";
const APP_ID = "test-app-id";

vi.mock("./env", () => ({
  ENV: {
    appId: APP_ID,
    cookieSecret: SECRET,
    databaseUrl: "",
    oAuthServerUrl: "",
    ownerOpenId: "",
    isProduction: false,
    forgeApiUrl: "",
    forgeApiKey: "",
  },
}));

async function signToken(
  claims: Record<string, unknown>,
  secret = SECRET
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setExpirationTime(Math.floor((Date.now() + 60_000) / 1000))
    .sign(new TextEncoder().encode(secret));
}

describe("sdk session signing/verification (session lifecycle)", () => {
  it("accepts a session whose name is an empty string (nameless user)", async () => {
    const { sdk } = await import("./sdk");
    const token = await sdk.signSession({
      openId: "open-1",
      appId: APP_ID,
      name: "",
    });
    const session = await sdk.verifySession(token);
    expect(session).toEqual({ openId: "open-1", appId: APP_ID, name: "" });
  });

  it("accepts a session with a name and echoes it back", async () => {
    const { sdk } = await import("./sdk");
    const token = await sdk.signSession({
      openId: "open-2",
      appId: APP_ID,
      name: "Ananya",
    });
    const session = await sdk.verifySession(token);
    expect(session).toEqual({
      openId: "open-2",
      appId: APP_ID,
      name: "Ananya",
    });
  });

  it("rejects a token signed with a different secret", async () => {
    const { sdk } = await import("./sdk");
    const forged = await signToken(
      { openId: "open-3", appId: APP_ID, name: "x" },
      "attacker-secret-that-is-definitely-not-ours-0123456789"
    );
    const session = await sdk.verifySession(forged);
    expect(session).toBeNull();
    expect(
      await jwtVerify(forged, new TextEncoder().encode(SECRET)).catch(
        () => null
      )
    ).toBeNull();
  });

  it("rejects a missing cookie value", async () => {
    const { sdk } = await import("./sdk");
    await expect(sdk.verifySession(undefined)).resolves.toBeNull();
    await expect(sdk.verifySession(null)).resolves.toBeNull();
    await expect(sdk.verifySession("")).resolves.toBeNull();
  });
});

describe("verifySession — app binding (security regression)", () => {
  beforeEach(() => {
    // The env module is mocked above; nothing else to wire per-test.
  });

  it("accepts a valid token bound to this app", async () => {
    const { sdk } = await import("./sdk");
    const token = await signToken({
      openId: "user-123",
      appId: APP_ID,
      name: "Test User",
    });

    const session = await sdk.verifySession(token);

    expect(session).not.toBeNull();
    expect(session?.openId).toBe("user-123");
    expect(session?.appId).toBe(APP_ID);
    expect(session?.name).toBe("Test User");
  });

  it("REJECTS a token minted for a different appId", async () => {
    const { sdk } = await import("./sdk");
    const token = await signToken({
      openId: "user-123",
      appId: "other-app-id",
      name: "Test User",
    });

    const session = await sdk.verifySession(token);

    expect(session).toBeNull();
  });

  it("tolerates an empty name claim (informational field)", async () => {
    const { sdk } = await import("./sdk");
    const token = await signToken({
      openId: "cron-job-1",
      appId: APP_ID,
      name: "",
    });

    const session = await sdk.verifySession(token);

    expect(session).not.toBeNull();
    expect(session?.name).toBe("");
  });

  it("rejects garbage input instead of throwing", async () => {
    const { sdk } = await import("./sdk");
    const session = await sdk.verifySession("not-a-jwt");
    expect(session).toBeNull();

    const nullSession = await sdk.verifySession(null);
    expect(nullSession).toBeNull();
  });
});
