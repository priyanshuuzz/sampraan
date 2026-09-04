import { describe, expect, it } from "vitest";
import type { Request } from "express";
import { getSessionCookieOptions } from "./cookies";

function requestWith(
  headers: Record<string, string | string[] | undefined>,
  protocol = "http"
): Request {
  return { headers, protocol } as unknown as Request;
}

describe("getSessionCookieOptions", () => {
  it("marks the cookie secure for an https request", () => {
    const options = getSessionCookieOptions(requestWith({}, "https"));
    expect(options).toEqual({
      httpOnly: true,
      path: "/",
      sameSite: "none",
      secure: true,
    });
  });

  it("keeps the cookie insecure on plain http without a proxy header", () => {
    const options = getSessionCookieOptions(requestWith({}));
    expect(options.secure).toBe(false);
  });

  it("honours x-forwarded-proto: https", () => {
    const options = getSessionCookieOptions(
      requestWith({ "x-forwarded-proto": "https" })
    );
    expect(options.secure).toBe(true);
  });

  it("honours a comma-separated x-forwarded-proto list containing https", () => {
    const options = getSessionCookieOptions(
      requestWith({ "x-forwarded-proto": "http,https" })
    );
    expect(options.secure).toBe(true);
  });

  it("does not treat an unrelated x-forwarded-proto as secure", () => {
    const options = getSessionCookieOptions(
      requestWith({ "x-forwarded-proto": "http" })
    );
    expect(options.secure).toBe(false);
  });

  it("trims and lowercases the x-forwarded-proto value", () => {
    const options = getSessionCookieOptions(
      requestWith({ "x-forwarded-proto": " HTTPS " })
    );
    expect(options.secure).toBe(true);
  });

  it("handles an array-valued x-forwarded-proto header", () => {
    const options = getSessionCookieOptions(
      requestWith({ "x-forwarded-proto": ["http", "https"] })
    );
    expect(options.secure).toBe(true);
  });

  it("always applies httpOnly, path /, and sameSite none", () => {
    const options = getSessionCookieOptions(requestWith({}, "https"));
    expect(options.httpOnly).toBe(true);
    expect(options.path).toBe("/");
    expect(options.sameSite).toBe("none");
  });
});
