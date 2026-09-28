import "dotenv/config";
import express from "express";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import { validateSecurityEnv, describeEnvironment } from "./env";
import { registerOAuthRoutes } from "./oauth";
import { appRouter } from "../routers";
import { createContext } from "./context";
import { serveStatic, setupVite } from "./vite";
import { getDb } from "../db";
import { blockchainService } from "../modules/blockchain/blockchain.service";
import { chainEventIndexer } from "../modules/blockchain/chain-event-indexer";
import { corsPolicy, rateLimit, requestLogger, securityHeaders } from "../common/security";
import { safeErrorHandler } from "../common/error-handler";
import { MAX_UPLOAD_BYTES } from "../modules/asset-content/content.service";
import { parseListenPort } from "../common/port";
import { describePqcProvider } from "../modules/crypto-assurance/pqc-key-provider";
import { checkSchemaReady } from "../modules/db/schema-readiness";
import { probeKubo } from "../modules/asset-content/kubo.probe";

/**
 * BUG-004 (QA #2): the chain event indexer existed but was never invoked, so
 * on-chain events never projected into the audit read model. This scheduler
 * runs the indexer periodically whenever a real chain is connected. All
 * failures are logged and retried on the next tick — indexing must never
 * crash the API server.
 */
const INDEXER_INTERVAL_MS = 30_000;
let indexerTimer: ReturnType<typeof setInterval> | null = null;

function startIndexerLoop(): void {
  if (indexerTimer) return;
  indexerTimer = setInterval(() => {
    void (async () => {
      try {
        const status = await blockchainService.getNetworkStatus();
        if (!status.connected) return;
        const result = await chainEventIndexer.indexRecentEvents();
        if (result.indexed > 0) {
          console.log(
            `[Indexer] Projected ${result.indexed} new chain event(s) into the audit read model (skipped ${result.skipped}, latest block ${result.latestBlock})`
          );
        }
      } catch (error) {
        console.error(
          "[Indexer] Chain event indexing failed:",
          error instanceof Error ? error.message : String(error)
        );
      }
    })();
  }, INDEXER_INTERVAL_MS);
  // Do not keep the process alive purely for the indexer.
  indexerTimer.unref?.();
}

function stopIndexerLoop(): void {
  if (indexerTimer) {
    clearInterval(indexerTimer);
    indexerTimer = null;
  }
}

function isPortAvailable(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const server = net.createServer();
    server.listen(port, () => {
      server.close(() => resolve(true));
    });
    server.on("error", () => resolve(false));
  });
}

async function findAvailablePort(startPort: number = 3000): Promise<number> {
  for (let port = startPort; port < startPort + 20; port++) {
    if (await isPortAvailable(port)) {
      return port;
    }
  }
  throw new Error(`No available port found starting from ${startPort}`);
}

async function startServer() {
  // Fail closed: refuse to boot with an unsafe configuration (e.g. missing
  // JWT secret in production) rather than silently signing forgeable tokens.
  validateSecurityEnv();

  const app = express();
  const server = createServer(app);
  // Do not advertise the framework in responses.
  app.disable("x-powered-by");
  // Behind a reverse proxy (nginx, a load balancer), req.ip would otherwise
  // be the PROXY's address: every client shares one rate-limit bucket (a
  // collective limit — safe but availability-hostile). TRUST_PROXY=1 opts in
  // to X-Forwarded-For resolution; it must be set ONLY when an actual proxy
  // fronts the app, otherwise clients could spoof their rate-limit identity.
  if (process.env.TRUST_PROXY === "1") {
    app.set("trust proxy", 1);
  }
  app.use(securityHeaders);
  app.use(corsPolicy);
  app.use(rateLimit());
  app.use(requestLogger);
  // FINAL-AUDIT FIX (upload body cap parity): content.createVersion is the
  // DOCUMENTED 20 MiB product upload path (MAX_UPLOAD_BYTES), but the global
  // 1 MB JSON cap rejected every real upload before the procedure could
  // enforce its own server-side limit — surfacing as a generic 500 from the
  // error handler. Register a dedicated JSON parser for the upload route
  // (method+path matched BEFORE the global parser) with headroom for base64
  // (~4/3) plus the batch/superjson envelope. body-parser marks req._body so
  // the later global parser skips double-parsing, and the tRPC mount below
  // receives the parsed body. The TRUE size limit is still enforced INSIDE
  // the procedure (decoded bytes > MAX_UPLOAD_BYTES → PAYLOAD_TOO_LARGE);
  // this cap is transport headroom, not the policy.
  const uploadLimitMb = Math.ceil((MAX_UPLOAD_BYTES * 4) / 3 / (1024 * 1024)) + 2;
  app.post("/api/trpc/content.createVersion", express.json({ limit: `${uploadLimitMb}mb` }));
  // Body limits: the API has no legitimate 50 MB payload. A tight cap
  // prevents trivial memory-exhaustion DoS via large JSON bodies.
  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ limit: "1mb", extended: true }));
  /**
   * GET /health — LIVENESS. Public by design (probes must not need credentials).
   *
   * Coarse on purpose: process is up, the database handle is usable, the chain
   * adapter reports its status (bounded by the RPC timeout so a hung node can
   * never stall the probe). No secret material, no stack traces, no row data.
   */
  app.get("/health", async (_req, res) => {
    const db = await getDb();
    const blockchain = await blockchainService.getNetworkStatus().catch(() => null);
    const pqc = describePqcProvider();
    res.json({
      api: "OK",
      database: db ? "CONNECTED" : "NOT_CONFIGURED",
      blockchain,
      cryptoAssurance: { provider: pqc.provider, postQuantum: pqc.postQuantum, productionSafe: pqc.productionSafe },
      environment: describeEnvironment(),
      uptimeSeconds: Math.round(process.uptime()),
    });
  });

  /**
   * GET /ready — READINESS (503 until the service can actually serve).
   *
   * Gates on the DATABASE, including its SCHEMA: a deployment that boots
   * against an unmigrated database would answer every request with a driver
   * error, so readiness explicitly checks for the tables the app cannot run
   * without. This is what makes a Railway/Render deploy fail visibly instead of
   * serving 500s (the release command runs `node dist/migrate.js` first).
   *
   * The chain layer deliberately does NOT gate readiness: anchoring is
   * best-effort by design (a chain outage must not drain the service from the
   * load balancer). Chain status is still reported for diagnostics.
   */
  app.get("/ready", async (_req, res) => {
    const db = await getDb();
    const blockchain = await blockchainService.getNetworkStatus().catch(() => null);
    const pqc = describePqcProvider();

    let schemaReady = false;
    let schemaDetail = "NOT_CHECKED";
    if (db) {
      try {
        const probe = await checkSchemaReady();
        schemaReady = probe.ready;
        schemaDetail = probe.detail;
      } catch (error) {
        schemaDetail = error instanceof Error ? error.message.slice(0, 120) : "SCHEMA_PROBE_FAILED";
      }
    }

    const ready = Boolean(db) && schemaReady;
    // Kubo diagnostics: a REAL bounded add→cat round-trip against the
    // self-hosted node (15s memo). NOT a readiness gate by design — content
    // writes fail closed on their own — but a deployment with a dead Kubo
    // must be visible to the operator, not discovered at first upload.
    const kubo = await probeKubo();
    res.status(ready ? 200 : 503).json({
      ready,
      database: db ? "CONNECTED" : "NOT_CONNECTED",
      schema: schemaDetail,
      kubo,
      blockchain,
      cryptoAssurance: { provider: pqc.provider, postQuantum: pqc.postQuantum },
      environment: describeEnvironment(),
    });
  });

  registerOAuthRoutes(app);
  // tRPC API
  app.use(
    "/api/trpc",
    createExpressMiddleware({
      router: appRouter,
      createContext,
    })
  );
  app.use(safeErrorHandler);
  // development mode uses Vite, production mode uses static files
  if (process.env.NODE_ENV === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // BUG-AUDIT-1: PORT=0 / garbage values previously produced an ephemeral or
  // broken binding (observed live with an inherited PORT=0). Validate first:
  // an explicitly-set but invalid PORT fails closed in production and falls
  // back to 3000 with a loud warning in development.
  const rawPort = process.env.PORT;
  const configuredPort = parseListenPort(rawPort);
  if (rawPort !== undefined && rawPort.trim() !== "" && configuredPort === null) {
    if (process.env.NODE_ENV === "production") {
      throw new Error(
        `[Production] PORT must be an integer between 1 and 65535 (received: "${rawPort}"). Refusing to start with an unusable port.`
      );
    }
    console.warn(
      `[Server] PORT "${rawPort}" is not a usable port (1-65535) — falling back to 3000.`
    );
  }
  const preferredPort = configuredPort ?? 3000;

  // Production must bind the EXACT configured port: behind an orchestrator,
  // health checks and reverse proxies target a known port, so silently
  // hopping to 3001+ turns a deploy into a false "unhealthy" outage.
  // Development keeps the convenience fallback for parallel dev servers.
  let port: number;
  if (process.env.NODE_ENV === "production") {
    const available = await isPortAvailable(preferredPort);
    if (!available) {
      throw new Error(
        `[Production] Port ${preferredPort} is already in use. Refusing to bind a different port — resolve the conflict (or set PORT) and restart.`
      );
    }
    port = preferredPort;
  } else {
    port = await findAvailablePort(preferredPort);
    if (port !== preferredPort) {
      console.log(`Port ${preferredPort} is busy, using port ${port} instead`);
    }
  }

  server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}/`);
    // Start projecting on-chain events into the audit read model (BUG-004).
    startIndexerLoop();
  });

  // Graceful shutdown: stop accepting new work, drain in-flight requests,
  // and exit. A second signal (container kill escalation) exits immediately.
  let shuttingDown = false;
  const shutdown = (signal: string) => {
    if (shuttingDown) {
      console.log(`[${signal}] repeated — exiting immediately`);
      process.exit(1);
    }
    shuttingDown = true;
    console.log(`[${signal}] shutting down gracefully...`);
    stopIndexerLoop();
    server.close(() => {
      console.log("[Shutdown] HTTP server closed; exiting");
      process.exit(0);
    });
    // Hard ceiling: never hang the operator longer than this.
    setTimeout(() => {
      console.error("[Shutdown] forced exit after drain timeout");
      process.exit(0);
    }, 10_000).unref();
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("unhandledRejection", (reason) => {
    // A rejected promise must never leave the process in an undefined state;
    // log structured and keep serving (it is not fatal by default).
    console.error(
      "[Process] Unhandled rejection:",
      reason instanceof Error ? `${reason.name}: ${reason.message}` : String(reason)
    );
  });
}

startServer().catch(console.error);
