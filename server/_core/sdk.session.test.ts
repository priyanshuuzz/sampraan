import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Session verification regression tests.
 *
 * createSessionToken signs `name: ""` when a user has no display name; the
 * verifier must still accept that session. openId and appId remain mandatory.
 * ENV snapshots process.env at module load, so the mock supplies the secret.
 */

const SECRET = "test-secret-for-vitest-only";

vi.mock("./env", () => ({
  ENV: {
    appId: "test-app",
    cookieSecret: SECRET,
    databaseUrl: "",
    oAuthServerUrl: "",
    ownerOpenId: "",
    isProduction: false,
    forgeApiUrl: "",
    forgeApiKey: "",
  },
}));

describe("sdk session signing/verification", () => {
  it("accepts a session whose name is an empty string (nameless user)", async () => {
    const { sdk } = await import("./sdk");
    const token = await sdk.signSession({
      openId: "open-1",
      appId: "app-1",
      name: "",
    });
    const session = await sdk.verifySession(token);
    expect(session).toEqual({ openId: "open-1", appId: "app-1", name: "" });
  });

  it("accepts a session with a name and echoes it back", async () => {
    const { sdk } = await import("./sdk");
    const token = await sdk.signSession({
      openId: "open-2",
      appId: "app-1",
      name: "Ananya",
    });
    const session = await sdk.verifySession(token);
    expect(session).toEqual({
      openId: "open-2",
      appId: "app-1",
      name: "Ananya",
    });
  });

  it("rejects a token signed with a different secret", async () => {
    const { sdk } = await import("./sdk");
    const { jwtVerify } = await import("jose");
    // Forge a token with a foreign secret and verify it must be rejected.
    const { SignJWT } = await import("jose");
    const forged = await new SignJWT({
      openId: "open-3",
      appId: "app-1",
      name: "x",
    })
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setExpirationTime(Math.floor((Date.now() + 60_000) / 1000))
      .sign(new TextEncoder().encode("attacker-secret"));
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
