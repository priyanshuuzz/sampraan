import type { NextFunction, Request, Response } from "express";

export function safeErrorHandler(error: unknown, _req: Request, res: Response, _next: NextFunction) {
  console.error("[API] Request failed", error instanceof Error ? error.message : "unknown error");
  if (res.headersSent) return;
  res.status(500).json({ error: "INTERNAL_SERVER_ERROR", message: "The request could not be completed safely." });
}
