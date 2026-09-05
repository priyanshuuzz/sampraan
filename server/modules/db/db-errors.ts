/**
 * Helpers to classify database driver errors after drizzle wraps them.
 *
 * drizzle-orm wraps every failed query in DrizzleQueryError with
 * message "Failed query: <sql>..." and stores the ORIGINAL mysql2 error
 * (with its code, e.g. ER_DUP_ENTRY) in error.cause. Checking
 * error.message alone therefore misses duplicate-key reverts entirely —
 * which is exactly how QA finding #1 (duplicate DID returned 500 instead
 * of 409) regressed. Always classify via these helpers.
 */

interface DriverLikeError {
  code?: string;
  errno?: number;
  sqlMessage?: string;
}

/** Unwrap the error.cause chain until we find a driver-level error. */
export function unwrapDriverError(error: unknown): unknown {
  let current: unknown = error;
  for (let depth = 0; depth < 10 && current instanceof Error; depth++) {
    const cause = (current as Error & { cause?: unknown }).cause;
    if (cause instanceof Error) {
      current = cause;
    } else {
      break;
    }
  }
  return current;
}

/** True when the (possibly wrapped) error is a MySQL duplicate-key failure. */
export function isDuplicateEntryError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  if (/duplicate entry|ER_DUP_ENTRY/i.test(message)) return true;
  const driver = unwrapDriverError(error) as DriverLikeError | null;
  if (driver && typeof driver === "object") {
    if (driver.code === "ER_DUP_ENTRY") return true;
    if (typeof driver.sqlMessage === "string" && /Duplicate entry/i.test(driver.sqlMessage)) {
      return true;
    }
  }
  return false;
}
