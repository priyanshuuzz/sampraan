import { describe, expect, it } from "vitest";
import { isDuplicateEntryError, unwrapDriverError } from "./db-errors";

/**
 * QA #1 regression tests: drizzle wraps mysql2 errors in DrizzleQueryError
 * ("Failed query: ...") with the driver error in .cause. Duplicate-key
 * detection MUST walk the cause chain — the message-only regex returned 500s.
 */
describe("isDuplicateEntryError", () => {
  it("matches a raw mysql2 duplicate error", () => {
    const raw = Object.assign(new Error("Duplicate entry 'x' for key 'identities.did_unique'"), {
      code: "ER_DUP_ENTRY",
      errno: 1062,
    });
    expect(isDuplicateEntryError(raw)).toBe(true);
  });

  it("matches a drizzle-wrapped duplicate error via the cause chain", () => {
    const driver = Object.assign(
      new Error("Duplicate entry 'did:web:x' for key 'identities.did_unique'"),
      { code: "ER_DUP_ENTRY", errno: 1062 }
    );
    const wrapped = new Error("Failed query: insert into `identities` (...) values (...)");
    (wrapped as Error & { cause?: unknown }).cause = driver;
    expect(isDuplicateEntryError(wrapped)).toBe(true);
  });

  it("matches a doubly-wrapped duplicate error", () => {
    const driver = Object.assign(new Error("dup"), { code: "ER_DUP_ENTRY" });
    const inner = new Error("Failed query: insert");
    (inner as Error & { cause?: unknown }).cause = driver;
    const outer = new Error("Request failed");
    (outer as Error & { cause?: unknown }).cause = inner;
    expect(isDuplicateEntryError(outer)).toBe(true);
  });

  it("does not match unrelated database errors", () => {
    const err = Object.assign(new Error("Connection lost"), { code: "ECONNRESET" });
    const wrapped = new Error("Failed query: select ...");
    (wrapped as Error & { cause?: unknown }).cause = err;
    expect(isDuplicateEntryError(wrapped)).toBe(false);
  });

  it("does not match plain errors without a cause", () => {
    expect(isDuplicateEntryError(new Error("some unrelated failure"))).toBe(false);
  });

  it("unwraps to the driver-level error", () => {
    const driver = Object.assign(new Error("dup"), { code: "ER_DUP_ENTRY" });
    const wrapped = new Error("Failed query: insert");
    (wrapped as Error & { cause?: unknown }).cause = driver;
    const unwrapped = unwrapDriverError(wrapped) as { code?: string };
    expect(unwrapped.code).toBe("ER_DUP_ENTRY");
  });
});
