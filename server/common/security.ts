import type { NextFunction, Request, Response } from "express";

/**
 * Security middleware: headers, CORS, rate limiting, structured request logging.
 *
 * Hardening rules applied here:
 * - CORS fails CLOSED: when CORS_ORIGIN is not configured, no cross-origin
 *   response is blessed. A misconfigured deployment must not silently allow
 *   credentialed requests from arbitrary origins.
 * - The rate limiter is memory-bounded: expired buckets are swept and the
 *   key space is capped, so it cannot be used as a memory-exhaustion vector.
 * - CSP and HSTS are applied in addition to the classic hardening headers.
 */

/** Max distinct rate-limit keys tracked before old entries are evicted. */
const RATE_LIMIT_MAX_KEYS = 10_000;
/** Sweep expired buckets at most once per interval (cheap opportunistic GC). */
const RATE_LIMIT_SWEEP_INTERVAL_MS = 30_000;

const requestCounts = new Map<string, { count: number; resetAt: number }>();
let lastSweepAt = 0;

function sweepExpiredBuckets(now: number, force = false): void {
  if (!force && now - lastSweepAt < RATE_LIMIT_SWEEP_INTERVAL_MS) {
    return;
  }
  lastSweepAt = now;
  requestCounts.forEach((bucket, key) => {
    if (bucket.resetAt <= now) {
      requestCounts.delete(key);
    }
  });
}

function isProductionRequest(): boolean {
  return process.env.NODE_ENV === "production";
}

function isSecureRequest(req: Request): boolean {
  const forwardedProto = req.headers["x-forwarded-proto"];
  if (typeof forwardedProto === "string" && forwardedProto.length > 0) {
    return forwardedProto.split(",")[0].trim() === "https";
  }
  return req.secure;
}

function contentSecurityPolicy(): string {
  // Development needs inline scripts for Vite HMR; production bundles are
  // fully same-origin assets, so scripts are locked to 'self' there.
  const scriptSrc = isProductionRequest()
    ? "script-src 'self'"
    : "script-src 'self' 'unsafe-inline'";
  // Tailwind/Radix components legitimately rely on inline style attributes.
  const styleSrc = "style-src 'self' 'unsafe-inline'";
  return [
    "default-src 'self'",
    scriptSrc,
    styleSrc,
    "img-src 'self' data:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ");
}

export function securityHeaders(
  req: Request,
  res: Response,
  next: NextFunction
) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Content-Security-Policy", contentSecurityPolicy());
  // HSTS only makes sense once the response travels over TLS; it is ignored
  // by browsers over plain HTTP, so setting it is always safe.
  if (isProductionRequest() || isSecureRequest(req)) {
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains"
    );
  }
  next();
}

export function corsPolicy(req: Request, res: Response, next: NextFunction) {
  const configuredOrigin = process.env.CORS_ORIGIN;
  const origin = req.headers.origin;

  if (configuredOrigin) {
    const allowlist = configuredOrigin
      .split(",")
      .map(value => value.trim())
      .filter(value => value.length > 0);
    if (origin && allowlist.includes(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }
  }
  // CORS_ORIGIN unset => no Access-Control-Allow-Origin is emitted at all.
  // Same-origin callers are unaffected (CORS never applies); unknown foreign
  // origins get no credentialed access. This is the fail-closed posture.

  if (req.method === "OPTIONS") {
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    );
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization, X-Requested-With"
    );
    res.setHeader("Access-Control-Max-Age", "600");
    res.status(204).end();
    return;
  }
  next();
}

export function rateLimit(windowMs = 60_000, maxRequests = 120) {
  return (req: Request, res: Response, next: NextFunction) => {
    const key = req.ip ?? "unknown";
    const now = Date.now();

    // Opportunistic GC keeps the map bounded even under key-space floods.
    sweepExpiredBuckets(now);
    if (requestCounts.size >= RATE_LIMIT_MAX_KEYS) {
      // Hard cap reached: evict the oldest entries. Deterministic and safe —
      // each entry is only a short-lived counter window.
      const overflow = requestCounts.size - RATE_LIMIT_MAX_KEYS + 1;
      const keys = requestCounts.keys();
      for (let i = 0; i < overflow; i++) {
        const oldest = keys.next();
        if (oldest.done) break;
        requestCounts.delete(oldest.value);
      }
    }

    const current = requestCounts.get(key);
    if (!current || current.resetAt <= now) {
      requestCounts.set(key, { count: 1, resetAt: now + windowMs });
      next();
      return;
    }
    current.count += 1;
    if (current.count > maxRequests) {
      const retryAfterSec = Math.max(1, Math.ceil((current.resetAt - now) / 1000));
      res.setHeader("Retry-After", String(retryAfterSec));
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
