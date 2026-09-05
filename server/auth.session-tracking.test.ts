import { beforeEach, describe, expect, it, vi } from "vitest";
import { COOKIE_NAME } from "../shared/const";
import type { TrpcContext } from "./_core/context";
import type { User } from "../drizzle/schema";

/**
 * SECURITY REGRESSION: server-side session tracking + logout revocation.
 *
 * H1 (audit): the OAuth login path never inserted the issued token into the
 * sessions table, so classifyPlatformSession returned UNTRACKED for every
 * real login and an administrator could never actually revoke a session.
 * The login flow must now track every minted token.
 *
 * M6 (audit): logout revoked only the bearer-token channel. A logout from a
 * cookie-based browser session left the token valid for replay. Logout must
 * revoke BOTH channels.
 */

const dbMocks = vi.hoisted(() => ({
  revokePlatformSession: vi.fn(async () => true),
  getUserByOpenId: vi.fn(),
  trackPlatformSession: vi.fn(async () => undefined),
  upsertUser: vi.fn(async () => undefined),
}));

vi.mock("./db", async (importOriginal: () => Promise<unknown>) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return { ...actual, ...dbMocks };
});

import { appRouter } from "./routers";
import { revokePlatformSession } from "./db";

function makeUser(): User {
  return {
    id: 1,
    openId: "user-open-1",
    name: "Operator",
    email: null,
    loginMethod: null,
    role: "user",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
  };
}

function makeContext(reqHeaders: Record<string, string | undefined>): TrpcContext {
  return {
    user: makeUser(),
    req: { protocol: "https", headers: reqHeaders } as TrpcContext["req"],
    res: {
      clearCookie: vi.fn(),
    } as unknown as TrpcContext["res"],
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("auth.logout — dual-channel session revocation", () => {
  it("revokes the session carried by the Authorization bearer header", async () => {
    const caller = appRouter.createCaller(
      makeContext({ authorization: "Bearer token-bearer-1" })
    );
    await caller.auth.logout();
    expect(revokePlatformSession).toHaveBeenCalledWith("token-bearer-1");
  });

  it("revokes the session carried by the cookie (previously missed)", async () => {
    const caller = appRouter.createCaller(
      makeContext({ cookie: `${COOKIE_NAME}=token-cookie-1; other=x` })
    );
    await caller.auth.logout();
    expect(revokePlatformSession).toHaveBeenCalledWith("token-cookie-1");
  });

  it("revokes BOTH channels when both are present, without duplicates", async () => {
    const caller = appRouter.createCaller(
      makeContext({
        authorization: "Bearer token-shared",
        cookie: `${COOKIE_NAME}=token-shared`,
      })
    );
    await caller.auth.logout();
    // The same token in both channels is one logical session: revoke once.
    expect(revokePlatformSession).toHaveBeenCalledTimes(1);
    expect(revokePlatformSession).toHaveBeenCalledWith("token-shared");
  });

  it("revokes each distinct channel token separately", async () => {
    const caller = appRouter.createCaller(
      makeContext({
        authorization: "Bearer token-bearer-2",
        cookie: `${COOKIE_NAME}=token-cookie-2`,
      })
    );
    await caller.auth.logout();
    expect(revokePlatformSession).toHaveBeenCalledTimes(2);
    expect(revokePlatformSession).toHaveBeenCalledWith("token-bearer-2");
    expect(revokePlatformSession).toHaveBeenCalledWith("token-cookie-2");
  });

  it("clears the cookie and reports success even with no tokens present", async () => {
    const ctx = makeContext({});
    const caller = appRouter.createCaller(ctx);
    const result = await caller.auth.logout();
    expect(result).toEqual({ success: true });
    expect(ctx.res.clearCookie).toHaveBeenCalledWith(
      COOKIE_NAME,
      expect.objectContaining({ maxAge: -1, sameSite: "lax", httpOnly: true })
    );
    expect(revokePlatformSession).not.toHaveBeenCalled();
  });
});
