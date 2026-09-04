import { describe, expect, it, vi } from "vitest";
import type { NextFunction, Request, Response } from "express";
import { safeErrorHandler } from "./error-handler";

function resSpy(headersSent = false) {
  const res = {
    headersSent,
    status: vi.fn(function () {
      return this;
    }),
    json: vi.fn(),
  };
  return res as unknown as Response;
}

describe("safeErrorHandler", () => {
  it("responds with a generic 500 and never echoes the error detail", () => {
    const logSpy = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    try {
      const res = resSpy();
      safeErrorHandler(
        new Error("secret database password leaked here"),
        {} as Request,
        res,
        vi.fn() as NextFunction
      );
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({
        error: "INTERNAL_SERVER_ERROR",
        message: "The request could not be completed safely.",
      });
      expect(logSpy).toHaveBeenCalledWith(
        "[API] Request failed",
        "secret database password leaked here"
      );
    } finally {
      logSpy.mockRestore();
    }
  });

  it("logs a fallback label for non-Error throwables", () => {
    const logSpy = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    try {
      const res = resSpy();
      safeErrorHandler(
        "just a string",
        {} as Request,
        res,
        vi.fn() as NextFunction
      );
      expect(logSpy).toHaveBeenCalledWith(
        "[API] Request failed",
        "unknown error"
      );
      expect(res.status).toHaveBeenCalledWith(500);
    } finally {
      logSpy.mockRestore();
    }
  });

  it("does not write a second response when headers were already sent", () => {
    const logSpy = vi
      .spyOn(console, "error")
      .mockImplementation(() => undefined);
    try {
      const res = resSpy(true);
      safeErrorHandler(
        new Error("late failure"),
        {} as Request,
        res,
        vi.fn() as NextFunction
      );
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
    } finally {
      logSpy.mockRestore();
    }
  });
});
