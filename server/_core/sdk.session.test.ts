import { describe, expect, it, beforeEach } from "vitest";
import { SignJWT } from "jose";
import { sdk } from "./sdk";
import { ENV } from "./env";

/**
 * SECURITY REGRESSION TESTS: session token verification.
 *
 * Historical vulnerabilities (fixed):
 * - verifySession accepted tokens minted for a different appId, so a token
 *   from another deployment sharing the same secret authenticated here.
 * - An empty `name` claim rejected otherwise legitimate sessions
 *   (reliability), and any payload-field changes were untested.
 *
 * Sessions are HS256-signed with ENV.cookieSecret and bound to ENV.appId.
 */

const SECRET = "test-secret-for-vitest-only-0123456789abcdef";

async function signToken(claims: Record<string, unknown>, secret = SECRET): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setExpirationTime(Math.floor((Date.now() + 60_000) / 1000))
    .sign(new TextEncoder().encode(secret));
}

beforeEach(() => {
  // Point the ENV-bound verifier at controlled values. ENV is a snapshot
  // taken at module load; override the properties for the test.
  (ENV as { appId: string }).appId = "test-app-id";
  (ENV as { cookieSecret: string }).cookieSecret = SECRET;
});

describe("verifySession — app binding", () => {
  it("accepts a valid token bound to this app", async () => {
    const token = await signToken({
      openId: "user-123",
      appId: "test-app-id",
      name: "Test User",
    });

    const session = await sdk.verifySession(token);

    expect(session).not.toBeNull();
    expect(session?.openId).toBe("user-123");
    expect(session?.appId).toBe("test-app-id");
    expect(session?.name).toBe("Test User");
  });

  it("REJECTS a token minted for a different appId", async () => {
    const token = await signToken({
      openId: "user-123",
      appId: "other-app-id",
      name: "Test User",
    });

    const session = await sdk.verifySession(token);

    expect(session).toBeNull();
  });

  it("rejects a token signed with a different secret", async () => {
    const token = await signToken(
      { openId: "user-123", appId: "test-app-id", name: "Test User" },
      "completely-different-secret-987654321"
    );

    const session = await sdk.verifySession(token);

    expect(session).toBeNull();
  });

  it("tolerates an empty name claim (informational field)", async () => {
    const token = await signToken({
      openId: "cron-job-1",
      appId: "test-app-id",
      name: "",
    });

    const session = await sdk.verifySession(token);

    expect(session).not.toBeNull();
    expect(session?.name).toBe("");
  });

  it("rejects garbage input instead of throwing", async () => {
    const session = await sdk.verifySession("not-a-jwt");
    expect(session).toBeNull();

    const nullSession = await sdk.verifySession(null);
    expect(nullSession).toBeNull();
  });
});
