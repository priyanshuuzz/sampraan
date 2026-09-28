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
 * Startup environment validation (fail-closed in production).
 *
 * Two classes of problem are distinguished deliberately:
 *
 *   FATAL  — the process must NOT boot, because booting would either be
 *            insecure (a forgeable session secret, an unbound session app id)
 *            or non-functional (no database URL at all).
 *   WARN   — the process boots and serves, but the operator is told loudly that
 *            a capability is degraded, so a "green" deploy never hides a
 *            missing integration.
 *
 * Rules that exist because the alternative failed silently before:
 *  - JWT_SECRET: absent/short ⇒ every token would be signed with a known-empty
 *    key (forgeable). Fatal in production.
 *  - VITE_APP_ID: absent ⇒ session tokens are not bound to this deployment, so
 *    a token minted for another deployment would be accepted. Fatal.
 *  - DATABASE_URL: absent ⇒ the app serves an empty, read-model-less UI and
 *    reports "NOT_CONFIGURED" on every probe. Fatal in production; the whole
 *    authorization model is DB-backed.
 *  - ASSET_CONTENT_MASTER_KEY: enforced by the storage module itself (fatal in
 *    production), because that key is what makes encrypted content unreadable.
 *  - CORS_ORIGIN: optional by design (same-origin deployments need nothing and
 *    an unset value fails CLOSED). Warned so a cross-origin deployment is not
 *    silently blocked in the browser.
 *  - TRUST_PROXY: warned when a proxied host is not opted in, because every
 *    client would otherwise share one rate-limit bucket.
 *  - PORT: validated by the port parser (fatal in production when unusable).
 *  - BLOCKCHAIN_* : optional — the chain layer is best-effort by design — but a
 *    malformed RPC URL or chain id is reported rather than ignored.
 */
export function validateSecurityEnv(): void {
  const problems: string[] = [];
  const warnings: string[] = [];

  // ---------------------------------------------------------------- secrets
  if (!ENV.cookieSecret || ENV.cookieSecret.length < 32) {
    if (isProduction) {
      problems.push(
        "JWT_SECRET is missing or shorter than 32 chars — session tokens would be forgeable.",
      );
    } else {
      warnings.push("JWT_SECRET is missing or weak (< 32 chars). Use a strong secret in production.");
    }
  }

  if (isProduction && !ENV.appId) {
    problems.push("VITE_APP_ID is not set — session tokens cannot be bound to this app.");
  }

  // ---------------------------------------------------------------- database
  if (!ENV.databaseUrl) {
    if (isProduction) {
      problems.push(
        "DATABASE_URL is not set — the authorization model, DID records and audit trail all live in the read model. Refusing to serve an unbacked deployment.",
      );
    } else {
      warnings.push("DATABASE_URL is not set — the API will start but every database-backed surface will be empty.");
    }
  } else if (!/^mysql(s)?:\/\//i.test(ENV.databaseUrl)) {
    // SAMPRAAN is MySQL (drizzle-orm/mysql2). A postgres:// URL pasted from a
    // generated template must fail loudly rather than at the first query.
    problems.push("DATABASE_URL must be a mysql:// connection string (this build uses the MySQL driver).");
  }

  // ---------------------------------------------------------------- platform URL
  const appUrl = process.env.APP_URL ?? process.env.PUBLIC_URL ?? "";
  if (isProduction && !appUrl) {
    warnings.push(
      "APP_URL is not set — absolute links (reports, share URLs) cannot be generated. Same-origin deployments can ignore this.",
    );
  }

  // ---------------------------------------------------------------- proxy / CORS
  if (!process.env.CORS_ORIGIN) {
    warnings.push(
      "CORS_ORIGIN is not set — cross-origin browsers get no credentialed access (fail-closed). Set it to your front-end origin(s) if the UI is served from another host.",
    );
  }
  if (isProduction && process.env.TRUST_PROXY !== "1") {
    warnings.push(
      "TRUST_PROXY is not set to 1 — if this app runs behind Railway/Render/a load balancer, all clients share ONE rate-limit bucket. Set TRUST_PROXY=1 only when a real proxy fronts the app.",
    );
  }

  // ---------------------------------------------------------------- blockchain
  const rpcUrl = process.env.BLOCKCHAIN_RPC_URL;
  if (rpcUrl && !/^https?:\/\//i.test(rpcUrl)) {
    problems.push(`BLOCKCHAIN_RPC_URL must be an http(s) URL (received "${rpcUrl.slice(0, 24)}…").`);
  }
  const chainId = process.env.BLOCKCHAIN_CHAIN_ID;
  if (chainId !== undefined && !/^\d+$/.test(chainId.trim())) {
    problems.push(`BLOCKCHAIN_CHAIN_ID must be an integer (received "${chainId}").`);
  }
  if (isProduction && !process.env.BLOCKCHAIN_PRIVATE_KEY) {
    warnings.push(
      "BLOCKCHAIN_PRIVATE_KEY is not set — on-chain anchoring and custody transfer will run in MOCK mode (no transaction is submitted). Set the operator key to enable the chain layer.",
    );
  }
  if (isProduction && !rpcUrl) {
    warnings.push("BLOCKCHAIN_RPC_URL is not set — the chain adapter falls back to the deployment manifest/default and will likely report disconnected.");
  }

  // ---------------------------------------------------------------- storage / PQC
  if (isProduction && !process.env.ASSET_CONTENT_MASTER_KEY) {
    // The storage module also refuses to run without it; reporting here makes
    // the failure list complete BEFORE the module-level throw.
    problems.push(
      "ASSET_CONTENT_MASTER_KEY is not set — encrypted asset content cannot be written or read in production.",
    );
  }
  if (isProduction && !process.env.IPFS_API_URL) {
    // Storage resolution also refuses (no silent local-FS fallback in
    // production); reporting here keeps the failure list complete FIRST.
    problems.push(
      "IPFS_API_URL is not set — production asset content requires the self-hosted Kubo IPFS node (e.g. http://127.0.0.1:5001/api/v0 on the node host).",
    );
  }
  if (isProduction && process.env.PQC_KEY_PROVIDER === "local-dev" && process.env.PQC_ALLOW_DEV_KEYS_IN_PRODUCTION !== "1") {
    warnings.push(
      "PQC_KEY_PROVIDER=local-dev is ignored in production (server-derived post-quantum keys are demo material). Register holder-held ML-DSA-65 keys instead.",
    );
  }

  // ---------------------------------------------------------------- report
  if (warnings.length > 0) {
    console.warn(
      `[Config] ${warnings.length} deployment warning(s):\n  - ${warnings.join("\n  - ")}`,
    );
  }

  if (problems.length > 0) {
    throw new Error(
      `[Security] Refusing to start with an unsafe configuration:\n  - ${problems.join("\n  - ")}`,
    );
  }
}

/**
 * Non-secret description of the runtime configuration, used by /health and
 * /ready so an operator can see WHAT is configured without reading logs.
 * Never includes a value that could be a secret — presence booleans only.
 */
export function describeEnvironment(): Record<string, unknown> {
  const integrations = {
    database: Boolean(process.env.DATABASE_URL),
    oauthIdp: Boolean(process.env.OAUTH_SERVER_URL),
    blockchainRpc: Boolean(process.env.BLOCKCHAIN_RPC_URL),
    blockchainOperatorKey: Boolean(process.env.BLOCKCHAIN_PRIVATE_KEY),
    assetContentMasterKey: Boolean(process.env.ASSET_CONTENT_MASTER_KEY),
    ipfs: Boolean(process.env.IPFS_API_URL),
    graphSubgraph: Boolean(process.env.GRAPH_SUBGRAPH_URL),
    corsAllowlist: Boolean(process.env.CORS_ORIGIN),
    trustProxy: process.env.TRUST_PROXY === "1",
  };
  return {
    nodeEnv: process.env.NODE_ENV ?? "development",
    // APP_VERSION is injected by the Docker build / platform release.
    version: process.env.APP_VERSION ?? "1.0.0",
    commit: process.env.APP_COMMIT ?? null,
    appId: ENV.appId || null,
    integrations,
  };
}
