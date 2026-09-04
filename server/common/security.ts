import type { NextFunction, Request, Response } from "express";

/**
 * Security middleware: headers, CORS, rate limiting, structured request logging.
 * Restored to the backend-foundation implementation.
 */

const requestCounts = new Map<string, { count: number; resetAt: number }>();

export function securityHeaders(
  _req: Request,
  res: Response,
  next: NextFunction
) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
}

export function corsPolicy(req: Request, res: Response, next: NextFunction) {
  const configuredOrigin = process.env.CORS_ORIGIN;
  const origin = req.headers.origin;
  if (
    origin &&
    (!configuredOrigin ||
      configuredOrigin
        .split(",")
        .map(value => value.trim())
        .includes(origin))
  ) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  if (req.method === "OPTIONS") {
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    );
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.status(204).end();
    return;
  }
  next();
}

export function rateLimit(windowMs = 60_000, maxRequests = 120) {
  return (req: Request, res: Response, next: NextFunction) => {
    const key = req.ip ?? "unknown";
    const now = Date.now();
    const current = requestCounts.get(key);
    if (!current || current.resetAt <= now) {
      requestCounts.set(key, { count: 1, resetAt: now + windowMs });
      next();
      return;
    }
    current.count += 1;
    if (current.count > maxRequests) {
      res
        .status(429)
        .json({ error: "RATE_LIMITED", message: "Too many requests" });
      return;
    }
    next();
  };
}

export function requestLogger(req: Request, res: Response, next: NextFunction) {
  const startedAt = Date.now();
  res.on("finish", () => {
    console.log(
      JSON.stringify({
        event: "http_request",
        method: req.method,
        path: req.path,
        status: res.statusCode,
        durationMs: Date.now() - startedAt,
      })
    );
  });
  next();
}
