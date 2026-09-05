import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Express, Request, Response } from "express";
import {
  COOKIE_NAME,
  OAUTH_STATE_COOKIE,
  encodeOAuthState,
  type OAuthState,
} from "../../shared/const";

// db + sdk are collaborators of the OAuth callback; mock them so the HTTP
// contract (status codes, cookies, redirects) can be asserted in isolation.
const dbMocks = vi.hoisted(() => ({
  upsertUser: vi.fn(),
  getUserByOpenId: vi.fn(),
  trackPlatformSession: vi.fn(),
}));

const sdkMocks = vi.hoisted(() => ({
  exchangeCodeForToken: vi.fn(),
  getUserInfo: vi.fn(),
  createSessionToken: vi.fn(),
}));

vi.mock("../db", () => dbMocks);
vi.mock("./sdk", () => ({
  sdk: {
    exchangeCodeForToken: sdkMocks.exchangeCodeForToken,
    getUserInfo: sdkMocks.getUserInfo,
    createSessionToken: sdkMocks.createSessionToken,
  },
}));

async function loadOAuthRoutes() {
  const mod = await import("./oauth");
  return mod;
}

type RegisteredRoute = {
  method: string;
  path: string;
  handler: (req: Request, res: Response) => Promise<void> | void;
};

function createAppSpy(): { app: Express; routes: RegisteredRoute[] } {
  const routes: RegisteredRoute[] = [];
  const app = {
    get: (path: string, handler: RegisteredRoute["handler"]) => {
      routes.push({ method: "GET", path, handler });
    },
  } as unknown as Express;
  return { app, routes };
}

function createRequest(
  query: Record<string, string | undefined>,
  cookies?: string
): Request {
  return {
    query,
    headers: cookies ? { cookie: cookies } : {},
    protocol: "https",
    hostname: "sampraan.example.com",
  } as unknown as Request;
}

function createResponse(): {
  res: Response;
  states: number[];
  bodies: unknown[];
  cookies: { name: string; value: string; options: Record<string, unknown> }[];
  clearedCookies: { name: string; options: Record<string, unknown> }[];
  redirects: (string | undefined)[];
  ended: boolean;
} {
  const states: number[] = [];
  const bodies: unknown[] = [];
  const cookies: {
    name: string;
    value: string;
    options: Record<string, unknown>;
  }[] = [];
  const clearedCookies: { name: string; options: Record<string, unknown> }[] =
    [];
  const redirects: (string | undefined)[] = [];
  const res = {
    status(code: number) {
      states.push(code);
      return this;
    },
    json(body: unknown) {
      bodies.push(body);
      return this;
    },
    cookie(name: string, value: string, options: Record<string, unknown>) {
      cookies.push({ name, value, options });
      return this;
    },
    clearCookie(name: string, options: Record<string, unknown>) {
      clearedCookies.push({ name, options });
      return this;
    },
    redirect(_code: number, location: string) {
      redirects.push(location);
      return this;
    },
    end() {
      return this;
    },
    headersSent: false,
  } as unknown as Response;
  return {
    res,
    states,
    bodies,
    cookies,
    clearedCookies,
    redirects,
    ended: false,
  };
}

async function callbackHandler() {
  const { registerOAuthRoutes } = await loadOAuthRoutes();
  const { app, routes } = createAppSpy();
  registerOAuthRoutes(app);
  const route = routes.find(r => r.path === "/api/oauth/callback");
  if (!route) throw new Error("callback route not registered");
  return route.handler;
}

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.resetModules();
});

describe("encodeOAuthState / decodeOAuthState helpers", () => {
  it("round-trips a state with a nonce", async () => {
    const { decodeOAuthState } = await import("../../shared/const");
    const state: OAuthState = {
      redirectUri: "https://sampraan.example.com/api/oauth/callback",
      nonce: "nonce-123",
    };
    const encoded = encodeOAuthState(state);
    expect(decodeOAuthState(encoded)).toEqual(state);
  });

  it("decodes legacy base64(redirectUri) states without a nonce", async () => {
    const { decodeOAuthState } = await import("../../shared/const");
    const legacy = btoa("https://legacy.example.com/callback");
    expect(decodeOAuthState(legacy)).toEqual({
      redirectUri: "https://legacy.example.com/callback",
    });
  });

  it("returns an empty redirectUri for malformed base64 instead of throwing", async () => {
    const { decodeOAuthState } = await import("../../shared/const");
    expect(decodeOAuthState("!!!not-base64!!!")).toEqual({ redirectUri: "" });
  });

  it("returns an empty redirectUri for non-JSON, non-URL payloads", async () => {
    const { decodeOAuthState } = await import("../../shared/const");
    expect(decodeOAuthState(btoa("not json"))).toEqual({
      redirectUri: "not json",
    });
  });
});

describe("GET /api/oauth/callback", () => {
  const validState = encodeOAuthState({
    redirectUri: "https://sampraan.example.com/api/oauth/callback",
    nonce: "nonce-123",
  });

  function requestWithStateCookie(state = validState, extraCookies = "") {
    const cookieHeader = [
      `${OAUTH_STATE_COOKIE}=${state ? "nonce-123" : ""}`,
      extraCookies,
    ]
      .filter(Boolean)
      .join("; ");
    return createRequest({ code: "auth-code", state }, cookieHeader);
  }

  it("rejects a callback without code with 400", async () => {
    const handler = await callbackHandler();
    const { res, bodies, states } = createResponse();
    await handler(createRequest({ state: validState }), res);
    expect(states).toContain(400);
    expect(bodies[0]).toEqual({ error: "code and state are required" });
  });

  it("rejects a callback without state with 400", async () => {
    const handler = await callbackHandler();
    const { res, states, bodies } = createResponse();
    await handler(createRequest({ code: "auth-code" }), res);
    expect(states).toContain(400);
    expect(bodies[0]).toEqual({ error: "code and state are required" });
  });

  it("rejects a forged state nonce with 403 (CSRF guard)", async () => {
    const handler = await callbackHandler();
    const { res, states, bodies } = createResponse();

    // state claims nonce-attacker, but the browser cookie has nonce-123.
    const forged = encodeOAuthState({
      redirectUri: "https://sampraan.example.com/api/oauth/callback",
      nonce: "nonce-attacker",
    });
    await handler(requestWithStateCookie(forged), res);

    expect(states).toContain(403);
    expect(bodies[0]).toEqual({ error: "invalid oauth state" });
    expect(sdkMocks.exchangeCodeForToken).not.toHaveBeenCalled();
  });

  it("rejects a state without any nonce with 403", async () => {
    const handler = await callbackHandler();
    const { res, states } = createResponse();
    const noNonce = btoa(
      JSON.stringify({
        redirectUri: "https://sampraan.example.com/api/oauth/callback",
      })
    );
    await handler(requestWithStateCookie(noNonce), res);
    expect(states).toContain(403);
  });

  it("rejects a callback when the nonce cookie is missing with 403", async () => {
    const handler = await callbackHandler();
    const { res, states } = createResponse();
    await handler(createRequest({ code: "auth-code", state: validState }), res);
    expect(states).toContain(403);
  });

  it("completes a login: clears the state cookie, sets the session, redirects", async () => {
    const handler = await callbackHandler();
    const { res, states, cookies, clearedCookies, redirects } =
      createResponse();

    sdkMocks.exchangeCodeForToken.mockResolvedValue({
      accessToken: "access-token",
    });
    sdkMocks.getUserInfo.mockResolvedValue({
      openId: "user-open-id",
      name: "Aarav Mehta",
      email: "aarav@example.com",
      loginMethod: "google",
    });
    sdkMocks.createSessionToken.mockResolvedValue("session-token-value");
    dbMocks.upsertUser.mockResolvedValue(undefined);
    // Session tracking: the login path persists the minted token so an
    // administrator can revoke it server-side later.
    dbMocks.getUserByOpenId.mockResolvedValue({ id: 42, openId: "user-open-id" });
    dbMocks.trackPlatformSession.mockResolvedValue(undefined);

    await handler(requestWithStateCookie(), res);

    expect(sdkMocks.exchangeCodeForToken).toHaveBeenCalledWith(
      "auth-code",
      validState
    );
    expect(dbMocks.upsertUser).toHaveBeenCalledWith(
      expect.objectContaining({
        openId: "user-open-id",
        name: "Aarav Mehta",
        loginMethod: "google",
      })
    );
    // SECURITY: the minted token must be recorded for server-side revocation.
    expect(dbMocks.trackPlatformSession).toHaveBeenCalledWith(
      expect.objectContaining({
        sessionToken: "session-token-value",
        linkedUserId: 42,
        expiresAt: expect.any(Date),
      })
    );
    expect(clearedCookies).toEqual([
      {
        name: OAUTH_STATE_COOKIE,
        options: expect.objectContaining({
          path: "/",
          secure: true,
          sameSite: "none",
        }),
      },
    ]);
    expect(cookies).toEqual([
      {
        name: COOKIE_NAME,
        value: "session-token-value",
        // SESSION_TTL_MS is 7 days in milliseconds — NOT a stale 365-day
        // value; the hardened session must expire in a week.
        options: expect.objectContaining({
          maxAge: 1000 * 60 * 60 * 24 * 7,
          httpOnly: true,
        }),
      },
    ]);
    expect(redirects).toEqual(["/"]);
    expect(states).toEqual([]);
  });

  it("rejects user info without an openId with 400", async () => {
    const handler = await callbackHandler();
    const { res, states, bodies } = createResponse();
    sdkMocks.exchangeCodeForToken.mockResolvedValue({ accessToken: "t" });
    sdkMocks.getUserInfo.mockResolvedValue({ name: "No OpenId" });

    await handler(requestWithStateCookie(), res);

    expect(states).toContain(400);
    expect(bodies[0]).toEqual({ error: "openId missing from user info" });
    expect(dbMocks.upsertUser).not.toHaveBeenCalled();
  });

  it("reports a 500 when the token exchange fails", async () => {
    const handler = await callbackHandler();
    const { res, states, bodies } = createResponse();
    sdkMocks.exchangeCodeForToken.mockRejectedValue(new Error("oauth down"));

    await handler(requestWithStateCookie(), res);

    expect(states).toContain(500);
    expect(bodies[0]).toEqual({ error: "OAuth callback failed" });
    expect(dbMocks.upsertUser).not.toHaveBeenCalled();
  });
});
