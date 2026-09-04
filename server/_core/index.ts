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
import { corsPolicy, rateLimit, requestLogger, securityHeaders } from "../common/security";
import { safeErrorHandler } from "../common/error-handler";

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
    const db = await getDb();
    const blockchain = await blockchainService.getNetworkStatus();
    const ready = Boolean(db);
    res.status(ready ? 200 : 503).json({ ready, database: db ? "CONNECTED" : "NOT_CONFIGURED", blockchain });
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
  const port = await findAvailablePort(preferredPort);

  if (port !== preferredPort) {
    console.log(`Port ${preferredPort} is busy, using port ${port} instead`);
  }

  server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}/`);
  });
}

startServer().catch(console.error);
