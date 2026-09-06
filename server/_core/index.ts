import "dotenv/config";
import express from "express";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import { validateSecurityEnv } from "./env";
import { registerOAuthRoutes } from "./oauth";
import { registerStorageProxy } from "./storageProxy";
import { appRouter } from "../routers";
import { createContext } from "./context";
import { serveStatic, setupVite } from "./vite";
import { getDb } from "../db";
import { blockchainService } from "../modules/blockchain/blockchain.service";
import { chainEventIndexer } from "../modules/blockchain/chain-event-indexer";
import { corsPolicy, rateLimit, requestLogger, securityHeaders } from "../common/security";
import { safeErrorHandler } from "../common/error-handler";

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
  app.use(securityHeaders);
  app.use(corsPolicy);
  app.use(rateLimit());
  app.use(requestLogger);
  // Body limits: the API has no legitimate 50 MB payload. A tight cap
  // prevents trivial memory-exhaustion DoS via large JSON bodies.
  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ limit: "1mb", extended: true }));
  app.get("/health", async (_req, res) => {
    // NOTE: intentionally public for liveness probes; returns coarse status
    // only (no secret material, no stack details).
    const db = await getDb();
    const blockchain = await blockchainService.getNetworkStatus();
    res.json({ api: "OK", database: db ? "CONNECTED" : "NOT_CONFIGURED", blockchain });
  });
  app.get("/ready", async (_req, res) => {
    // Readiness gates on the DATABASE only: the chain layer is deliberately
    // best-effort (anchoring never blocks identity/asset operations), so a
    // chain outage must not drain the service from the load balancer.
    // Chain status is still REPORTED (bounded by the RPC timeout) for
    // diagnostics, but it does not flip readiness.
    const db = await getDb();
    const ready = Boolean(db);
    const blockchain = await blockchainService.getNetworkStatus().catch(() => null);
    res.status(ready ? 200 : 503).json({ ready, database: db ? "CONNECTED" : "NOT_CONNECTED", blockchain });
  });
  registerStorageProxy(app);
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

  const preferredPort = parseInt(process.env.PORT || "3000");

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
