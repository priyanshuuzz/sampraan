const isProduction = process.env.NODE_ENV === "production";

export const ENV = {
  appId: process.env.VITE_APP_ID ?? "",
  cookieSecret: process.env.JWT_SECRET ?? "",
  databaseUrl: process.env.DATABASE_URL ?? "",
  oAuthServerUrl: process.env.OAUTH_SERVER_URL ?? "",
  ownerOpenId: process.env.OWNER_OPEN_ID ?? "",
  isProduction,
  forgeApiUrl: process.env.BUILT_IN_FORGE_API_URL ?? "",
  forgeApiKey: process.env.BUILT_IN_FORGE_API_KEY ?? "",
};

/**
 * Startup security validation (fail-closed in production).
 *
 * A missing JWT secret would otherwise silently downgrade every session
 * token to being signed with an empty-string key — i.e. forgeable by
 * anyone. That must never happen quietly.
 */
export function validateSecurityEnv(): void {
  const problems: string[] = [];

  if (!ENV.cookieSecret || ENV.cookieSecret.length < 32) {
    if (isProduction) {
      problems.push(
        "JWT_SECRET is missing or shorter than 32 chars — session tokens would be forgeable."
      );
    } else {
      // Dev convenience is allowed, but say it loudly once.
      console.warn(
        "[Security] JWT_SECRET is missing or weak (< 32 chars). Use a strong secret in production."
      );
    }
  }

  if (isProduction && !ENV.appId) {
    problems.push("VITE_APP_ID is not set — session tokens cannot be bound to this app.");
  }

  if (problems.length > 0) {
    throw new Error(
      `[Security] Refusing to start with an unsafe configuration:\n  - ${problems.join("\n  - ")}`
    );
  }
}
