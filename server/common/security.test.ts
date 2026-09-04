import { beforeEach, describe, expect, it, vi } from "vitest";
import type { NextFunction, Request, Response } from "express";
import {
  corsPolicy,
  rateLimit,
  requestLogger,
  securityHeaders,
} from "./security";

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
});

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
});

describe("corsPolicy", () => {
  it("reflects any origin when CORS_ORIGIN is unset", () => {
    delete process.env.CORS_ORIGIN;
    const next: NextFunction = vi.fn();
    const { res, headers } = resSpy();
    corsPolicy(
      reqSpy({ headers: { origin: "https://any.example.com" } }),
      res,
      next
    );
    expect(headers["Access-Control-Allow-Origin"]).toBe(
      "https://any.example.com"
    );
    expect(headers["Vary"]).toBe("Origin");
    expect(headers["Access-Control-Allow-Credentials"]).toBe("true");
    expect(next).toHaveBeenCalled();
  });

  it("allows an origin present in the CORS_ORIGIN allowlist", () => {
    process.env.CORS_ORIGIN = "https://a.example.com, https://b.example.com";
    const next: NextFunction = vi.fn();
    const { res, headers } = resSpy();
    corsPolicy(
      reqSpy({ headers: { origin: "https://b.example.com" } }),
      res,
      next
    );
    expect(headers["Access-Control-Allow-Origin"]).toBe(
      "https://b.example.com"
    );
    expect(next).toHaveBeenCalled();
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
    expect(headers["Access-Control-Allow-Headers"]).toBe(
      "Content-Type, Authorization"
    );
    expect(res.status).toHaveBeenCalledWith(204);
    expect(res.end).toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it("skips CORS headers when no origin header is present", () => {
    delete process.env.CORS_ORIGIN;
    const next: NextFunction = vi.fn();
    const { res, headers } = resSpy();
    corsPolicy(reqSpy(), res, next);
    expect(headers["Access-Control-Allow-Origin"]).toBeUndefined();
    expect(next).toHaveBeenCalled();
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
});

describe("rateLimit", () => {
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
    const ip = uniqueIp(); // reserve a slot so 'unknown' stays deterministic
    void ip;
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
});

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
