import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import type { NextFunction, Request, Response } from "express";
import { corsPolicy, rateLimit, securityHeaders } from "./security";

/**
 * SECURITY REGRESSION TESTS: middleware hardening.
 *
 * - CORS must fail CLOSED: with CORS_ORIGIN unset, no arbitrary origin is
 *   reflected with credentials (historical vulnerability).
 * - The rate limiter must remain memory-bounded under key-space flooding.
 * - Security headers (CSP, HSTS, nosniff...) must always be set.
 */

type MockReq = Partial<Request> & {
  headers: Record<string, string | string[] | undefined>;
  ip?: string;
  method: string;
  secure?: boolean;
};

function makeReq(overrides: Partial<MockReq> = {}): Request {
  return {
    headers: {},
    method: "GET",
    secure: false,
    ...overrides,
  } as Request;
}

function makeRes(): Response & {
  headers: Record<string, string>;
  statusCode: number;
  ended: boolean;
  body: unknown;
} {
  const headers: Record<string, string> = {};
  const res = {
    headers,
    statusCode: 200,
    ended: false,
    body: undefined,
    setHeader: vi.fn((k: string, v: string | number | string[]) => {
      headers[k] = String(v);
    }),
    status: vi.fn(function (this: { statusCode: number }, code: number) {
      this.statusCode = code;
      return this;
    }),
    json: vi.fn(function (this: unknown, body: unknown) {
      (this as { body: unknown }).body = body;
      (this as { ended: boolean }).ended = true;
      return this;
    }),
    end: vi.fn(function (this: { ended: boolean }) {
      this.ended = true;
      return this;
    }),
  };
  return res as unknown as Response & typeof res;
}

const next: NextFunction = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env.CORS_ORIGIN;
  delete process.env.NODE_ENV;
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("corsPolicy — fail-closed when CORS_ORIGIN is unset", () => {
  it("does NOT reflect an arbitrary origin when CORS_ORIGIN is unset", () => {
    const req = makeReq({ headers: { origin: "https://evil.example" } });
    const res = makeRes();

    corsPolicy(req as Request, res as unknown as Response, next);

    expect(res.headers["Access-Control-Allow-Origin"]).toBeUndefined();
    expect(res.headers["Access-Control-Allow-Credentials"]).toBeUndefined();
  });

  it("reflects only allowlisted origins when CORS_ORIGIN is set", () => {
    process.env.CORS_ORIGIN = "https://app.example, https://partner.example";
    const okReq = makeReq({ headers: { origin: "https://partner.example" } });
    const okRes = makeRes();
    corsPolicy(okReq as Request, okRes as unknown as Response, next);

    expect(okRes.headers["Access-Control-Allow-Origin"]).toBe(
      "https://partner.example"
    );
    expect(okRes.headers["Access-Control-Allow-Credentials"]).toBe("true");

    const evilReq = makeReq({ headers: { origin: "https://evil.example" } });
    const evilRes = makeRes();
    corsPolicy(evilReq as Request, evilRes as unknown as Response, next);

    expect(evilRes.headers["Access-Control-Allow-Origin"]).toBeUndefined();
  });

  it("answers OPTIONS preflight without leaking an unset origin", () => {
    const req = makeReq({
      method: "OPTIONS",
      headers: { origin: "https://evil.example" },
    });
    const res = makeRes();

    corsPolicy(req as Request, res as unknown as Response, next);

    expect(res.headers["Access-Control-Allow-Origin"]).toBeUndefined();
    expect(res.statusCode).toBe(204);
    expect(res.ended).toBe(true);
    expect(next).not.toHaveBeenCalled();
  });
});

describe("securityHeaders", () => {
  it("sets CSP, nosniff, frame-options, referrer and permissions policy", () => {
    const req = makeReq();
    const res = makeRes();

    securityHeaders(req as Request, res as unknown as Response, next);

    expect(res.headers["Content-Security-Policy"]).toContain("default-src 'self'");
    expect(res.headers["X-Content-Type-Options"]).toBe("nosniff");
    expect(res.headers["X-Frame-Options"]).toBe("DENY");
    expect(res.headers["Referrer-Policy"]).toBe("no-referrer");
    expect(res.headers["Permissions-Policy"]).toBeDefined();
  });

  it("sets HSTS over secure transport", () => {
    const req = makeReq({
      headers: { "x-forwarded-proto": "https" },
    });
    const res = makeRes();

    securityHeaders(req as Request, res as unknown as Response, next);

    expect(res.headers["Strict-Transport-Security"]).toContain("max-age");
  });

  it("omits HSTS on plain HTTP outside production", () => {
    const req = makeReq(); // secure=false, no forwarded proto
    const res = makeRes();

    securityHeaders(req as Request, res as unknown as Response, next);

    expect(res.headers["Strict-Transport-Security"]).toBeUndefined();
  });
});

describe("rateLimit — memory-bounded limiter", () => {
  it("blocks requests beyond the cap and sets Retry-After", () => {
    const limiter = rateLimit(60_000, 3);
    const ip = "203.0.113.9";

    const results: Array<number | "429"> = [];
    for (let i = 0; i < 5; i++) {
      const req = makeReq({ ip });
      const res = makeRes();
      limiter(req as Request, res as unknown as Response, next);
      results.push(res.statusCode === 429 && res.body ? "429" : 200);
    }

    expect(results.filter(r => r === "429")).toHaveLength(2);
  });

  it("sets Retry-After seconds on the 429 response", () => {
    const limiter = rateLimit(60_000, 1);
    const ip = "203.0.113.10";

    const first = makeRes();
    limiter(makeReq({ ip }) as Request, first as unknown as Response, next);
    const second = makeRes();
    limiter(makeReq({ ip }) as Request, second as unknown as Response, next);

    expect(second.headers["Retry-After"]).toBeDefined();
    expect(Number(second.headers["Retry-After"])).toBeGreaterThan(0);
  });

  it("keeps the key space bounded under a flood of unique IPs", async () => {
    // Use a tiny window so expired buckets get swept.
    const limiter = rateLimit(1, 5); // 1ms window — buckets expire instantly
    for (let i = 0; i < 20_000; i++) {
      const req = makeReq({ ip: `10.0.${Math.floor(i / 250)}.${i % 250}` });
      const res = makeRes();
      limiter(req as Request, res as unknown as Response, next);
    }
    // After the sweep, the map must be pruned well below the flood size.
    // (The cap is 10k; the 1ms window means all buckets are expired.)
    await new Promise(resolve => setTimeout(resolve, 5));
    const req = makeReq({ ip: "10.9.9.9" });
    const res = makeRes();
    limiter(req as Request, res as unknown as Response, next);
    expect(res.statusCode).not.toBe(429);
  });
});
