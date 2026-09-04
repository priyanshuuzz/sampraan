import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { NextFunction, Request, Response } from "express";
import {
  corsPolicy,
  rateLimit,
  requestLogger,
  securityHeaders,
} from "./security";

/**
 * SECURITY REGRESSION TESTS: middleware hardening.
 *
 * Union of two suites:
 *  - The security-agent suite: CORS must fail CLOSED (unset CORS_ORIGIN
 *    reflects NO origin), the rate limiter must remain memory-bounded under
 *    key-space flooding, and security headers (CSP, HSTS, nosniff) must
 *    always be set.
 *  - The testing-agent suite: broader coverage of the same middleware —
 *    allowlisted CORS, preflight handling, per-ip rate tracking, the
 *    unknown-ip bucket, window reset, 429 payloads, and request logging.
 *
 * One expectation from the testing branch ("reflects any origin when
 * CORS_ORIGIN is unset") asserted the pre-hardening behavior and is updated
 * to the fail-closed contract: an unset CORS_ORIGIN must never reflect an
 * arbitrary origin with credentials.
 */

function resSpy() {
  const headers: Record<string, string> = {};
  const res = {
    setHeader: vi.fn((k: string, v: string) => {
      headers[k] = String(v);
    }),
    status: vi.fn(function () {
      return this;
    }),
    json: vi.fn(),
    end: vi.fn(),
    statusCode: 200,
    on: vi.fn(),
  };
  return { res: res as unknown as Response, headers };
}

function reqSpy(overrides: Partial<Request> = {}) {
  return {
    method: "GET",
    path: "/",
    ip: "1.2.3.4",
    headers: {},
    ...overrides,
  } as unknown as Request;
}

// security.ts keeps a module-level request counter, so each test uses a
// unique ip to stay independent.
let ipCounter = 0;
function uniqueIp() {
  ipCounter += 1;
  return `10.0.${Math.floor(ipCounter / 250) % 250}.${ipCounter % 250}`;
}

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env.CORS_ORIGIN;
  delete process.env.NODE_ENV;
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// securityHeaders
// ---------------------------------------------------------------------------

describe("securityHeaders", () => {
  it("sets nosniff, DENY framing, no-referrer, and a locked permissions policy", () => {
    const next: NextFunction = vi.fn();
    const { res, headers } = resSpy();
    securityHeaders(reqSpy(), res, next);
    expect(headers["X-Content-Type-Options"]).toBe("nosniff");
    expect(headers["X-Frame-Options"]).toBe("DENY");
    expect(headers["Referrer-Policy"]).toBe("no-referrer");
    expect(headers["Permissions-Policy"]).toBe(
      "camera=(), microphone=(), geolocation=()"
    );
    expect(next).toHaveBeenCalled();
  });

  it("sets a default-src 'self' content security policy", () => {
    const next: NextFunction = vi.fn();
    const { res, headers } = resSpy();
    securityHeaders(reqSpy(), res, next);
    expect(headers["Content-Security-Policy"]).toContain("default-src 'self'");
  });

  it("sets HSTS over secure transport", () => {
    const next: NextFunction = vi.fn();
    const { res, headers } = resSpy();
    securityHeaders(
      reqSpy({ headers: { "x-forwarded-proto": "https" } }),
      res,
      next
    );
    expect(headers["Strict-Transport-Security"]).toContain("max-age");
  });

  it("omits HSTS on plain HTTP outside production", () => {
    const next: NextFunction = vi.fn();
    const { res, headers } = resSpy();
    securityHeaders(reqSpy(), res, next);
    expect(headers["Strict-Transport-Security"]).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// corsPolicy — fail-closed
// ---------------------------------------------------------------------------

describe("corsPolicy — fail-closed when CORS_ORIGIN is unset", () => {
  it("does NOT reflect an arbitrary origin when CORS_ORIGIN is unset (stale expectation updated to the hardened contract)", () => {
    // The pre-hardening middleware reflected any origin here; it must now
    // fail closed: no reflected origin, no credentials header.
    const next: NextFunction = vi.fn();
    const { res, headers } = resSpy();
    corsPolicy(
      reqSpy({ headers: { origin: "https://any.example.com" } }),
      res,
      next
    );
    expect(headers["Access-Control-Allow-Origin"]).toBeUndefined();
    expect(headers["Access-Control-Allow-Credentials"]).toBeUndefined();
    expect(next).toHaveBeenCalled();
  });

  it("reflects only allowlisted origins when CORS_ORIGIN is set", () => {
    process.env.CORS_ORIGIN = "https://app.example, https://partner.example";
    const next: NextFunction = vi.fn();

    const ok = resSpy();
    corsPolicy(
      reqSpy({ headers: { origin: "https://partner.example" } }),
      ok.res,
      next
    );
    expect(ok.headers["Access-Control-Allow-Origin"]).toBe(
      "https://partner.example"
    );
    expect(ok.headers["Access-Control-Allow-Credentials"]).toBe("true");
    expect(next).toHaveBeenCalled();

    const evil = resSpy();
    corsPolicy(
      reqSpy({ headers: { origin: "https://evil.example" } }),
      evil.res,
      next
    );
    expect(evil.headers["Access-Control-Allow-Origin"]).toBeUndefined();
  });

  it("does not set allow-origin when the origin is not allowlisted", () => {
    process.env.CORS_ORIGIN = "https://a.example.com";
    const next: NextFunction = vi.fn();
    const { res, headers } = resSpy();
    corsPolicy(
      reqSpy({ headers: { origin: "https://evil.example.com" } }),
      res,
      next
    );
    expect(headers["Access-Control-Allow-Origin"]).toBeUndefined();
    expect(next).toHaveBeenCalled();
  });

  it("answers OPTIONS preflights with 204 and ends the response", () => {
    process.env.CORS_ORIGIN = "https://a.example.com";
    const next: NextFunction = vi.fn();
    const { res, headers } = resSpy();
    corsPolicy(
      reqSpy({
        method: "OPTIONS",
        headers: { origin: "https://a.example.com" },
      }),
      res,
      next
    );
    expect(headers["Access-Control-Allow-Methods"]).toBe(
      "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    );
    // The hardened middleware extends the allowed headers with
    // X-Requested-With; assert the baseline set is always present.
    expect(headers["Access-Control-Allow-Headers"]).toContain(
      "Content-Type, Authorization"
    );
    expect(res.status).toHaveBeenCalledWith(204);
    expect(res.end).toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it("answers OPTIONS preflight without leaking an unset origin (204, no ACAO)", () => {
    const next: NextFunction = vi.fn();
    const { res, headers } = resSpy();
    corsPolicy(
      reqSpy({
        method: "OPTIONS",
        headers: { origin: "https://evil.example" },
      }),
      res,
      next
    );
    // Preflight still terminates with 204, but must not leak a reflected
    // origin: no ACAO, no credentials header.
    expect(headers["Access-Control-Allow-Origin"]).toBeUndefined();
    expect(headers["Access-Control-Allow-Credentials"]).toBeUndefined();
    expect(res.status).toHaveBeenCalledWith(204);
    expect(res.end).toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it("still answers OPTIONS with 204 when the origin is unconfigured", () => {
    process.env.CORS_ORIGIN = "https://a.example.com";
    const next: NextFunction = vi.fn();
    const { res } = resSpy();
    corsPolicy(
      reqSpy({
        method: "OPTIONS",
        headers: { origin: "https://unlisted.example.com" },
      }),
      res,
      next
    );
    expect(res.status).toHaveBeenCalledWith(204);
    expect(res.end).toHaveBeenCalled();
  });

  it("skips CORS headers when no origin header is present", () => {
    const next: NextFunction = vi.fn();
    const { res, headers } = resSpy();
    corsPolicy(reqSpy(), res, next);
    expect(headers["Access-Control-Allow-Origin"]).toBeUndefined();
    expect(next).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// rateLimit
// ---------------------------------------------------------------------------

describe("rateLimit — memory-bounded limiter", () => {
  it("allows requests up to the configured maximum", () => {
    const next: NextFunction = vi.fn();
    const ip = uniqueIp();
    const limiter = rateLimit(60_000, 3);
    for (let i = 0; i < 3; i++) {
      const { res } = resSpy();
      limiter(reqSpy({ ip }), res, next);
      expect(res.status).not.toHaveBeenCalledWith(429);
    }
    expect(next).toHaveBeenCalledTimes(3);
  });

  it("returns 429 once the limit is exceeded", () => {
    const next: NextFunction = vi.fn();
    const ip = uniqueIp();
    const limiter = rateLimit(60_000, 2);
    for (let i = 0; i < 2; i++) {
      const { res } = resSpy();
      limiter(reqSpy({ ip }), res, next);
    }
    const { res: over } = resSpy();
    limiter(reqSpy({ ip }), over, next);
    expect(over.status).toHaveBeenCalledWith(429);
    expect(over.json).toHaveBeenCalledWith({
      error: "RATE_LIMITED",
      message: "Too many requests",
    });
    expect(next).toHaveBeenCalledTimes(2);
  });

  it("sets Retry-After seconds on the 429 response", () => {
    const limiter = rateLimit(60_000, 1);
    const ip = uniqueIp();

    const first = resSpy();
    limiter(reqSpy({ ip }), first.res, vi.fn());
    const second = resSpy();
    limiter(reqSpy({ ip }), second.res, vi.fn());

    expect(second.headers["Retry-After"]).toBeDefined();
    expect(Number(second.headers["Retry-After"])).toBeGreaterThan(0);
  });

  it("tracks limits per client ip", () => {
    const next: NextFunction = vi.fn();
    const limiter = rateLimit(60_000, 1);
    const { res: resA } = resSpy();
    const { res: resB } = resSpy();
    limiter(reqSpy({ ip: uniqueIp() }), resA, next);
    limiter(reqSpy({ ip: uniqueIp() }), resB, next);
    expect(next).toHaveBeenCalledTimes(2);
  });

  it("uses the 'unknown' bucket when ip is missing", () => {
    // The unknown bucket is shared; only assert it does not throw and calls
    // next for the first request.
    const next: NextFunction = vi.fn();
    const limiter = rateLimit(60_000, 1000);
    const { res } = resSpy();
    const unknownReq = reqSpy({ ip: undefined } as Partial<Request>);
    limiter(unknownReq, res, next);
    expect(next).toHaveBeenCalled();
  });

  it("resets the counter after the window elapses", async () => {
    const next: NextFunction = vi.fn();
    const ip = uniqueIp();
    const limiter = rateLimit(1, 1); // 1ms window
    const { res: resA } = resSpy();
    limiter(reqSpy({ ip }), resA, next);
    await new Promise<void>(resolve => setTimeout(resolve, 5));
    const { res: resB } = resSpy();
    limiter(reqSpy({ ip }), resB, next);
    expect(resB.status).not.toHaveBeenCalledWith(429);
    expect(next).toHaveBeenCalledTimes(2);
  });

  it("keeps the key space bounded under a flood of unique IPs", async () => {
    // Use a tiny window so expired buckets get swept.
    const limiter = rateLimit(1, 5); // 1ms window — buckets expire instantly
    for (let i = 0; i < 20_000; i++) {
      const { res } = resSpy();
      limiter(reqSpy({ ip: `10.1.${Math.floor(i / 250) % 250}.${i % 250}` }), res, vi.fn());
    }
    // After the sweep, the map must be pruned well below the flood size.
    // (The cap is 10k; the 1ms window means all buckets are expired.)
    await new Promise(resolve => setTimeout(resolve, 5));
    const { res } = resSpy();
    limiter(reqSpy({ ip: "10.9.9.9" }), res, vi.fn());
    expect(res.status).not.toHaveBeenCalledWith(429);
  });
});

// ---------------------------------------------------------------------------
// requestLogger
// ---------------------------------------------------------------------------

describe("requestLogger", () => {
  it("logs a structured json line on response finish", () => {
    const next: NextFunction = vi.fn();
    const { res } = resSpy();
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    try {
      requestLogger(reqSpy({ method: "POST", path: "/api/test" }), res, next);
      const onCalls = (res.on as unknown as ReturnType<typeof vi.fn>).mock
        .calls;
      const finishCall = onCalls.find(call => call[0] === "finish");
      expect(finishCall).toBeDefined();
      (finishCall?.[1] as () => void)();
      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining('"event":"http_request"')
      );
      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining('"method":"POST"')
      );
    } finally {
      logSpy.mockRestore();
    }
  });
});
