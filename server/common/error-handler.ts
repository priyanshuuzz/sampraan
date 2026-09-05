import type { NextFunction, Request, Response } from "express";

/**
 * Safe, non-empty error description for logs, audit evidence, and API
 * messages. Node network errors (e.g. ethers' AggregateError on a refused
 * blockchain connection) can carry an EMPTY .message — surfacing "" to an
 * operator would hide the real cause, so fall back to the error name and
 * code until something descriptive is available.
 */
export function describeError(error: unknown): string {
  if (error instanceof Error) {
    const parts = [error.message, error.name];
    const code = (error as Error & { code?: unknown }).code;
    if (code !== undefined && code !== null) parts.push(String(code));
    const described = parts.filter(part => typeof part === "string" && part.length > 0);
    if (described.length > 0) return described.join(" ").trim();
  }
  return String(error);
}

export function safeErrorHandler(error: unknown, _req: Request, res: Response, _next: NextFunction) {
  console.error("[API] Request failed", error instanceof Error ? error.message : "unknown error");
  if (res.headersSent) return;
  res.status(500).json({ error: "INTERNAL_SERVER_ERROR", message: "The request could not be completed safely." });
}
