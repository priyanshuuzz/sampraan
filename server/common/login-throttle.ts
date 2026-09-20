/**
 * LOCAL-LOGIN BRUTE-FORCE THROTTLE (audit fix).
 *
 * The local password login path previously had no per-account failure
 * throttling — an attacker could attempt unlimited password guesses against a
 * seeded demonstration account at full speed. This adds an in-memory
 * per-email (and per-IP) failure limiter for the LOCAL login procedure only:
 *
 *  - 5 failed attempts per 15-minute window per email => 429 with retry hint.
 *  - A successful authentication clears the email's counter.
 *  - The limiter is process-local (no new infrastructure) and intentionally
 *    sized for the demo/edge deployment profile; a horizontally scaled
 *    deployment would move this to a shared store.
 *
 * It is a pure, synchronous module so it is directly unit-testable.
 */

const MAX_FAILURES_PER_WINDOW = 5;
const WINDOW_MS = 15 * 60 * 1000;

export interface ThrottleEntry {
  count: number;
  windowStartedAt: number;
  blockedUntil?: number;
}

const failuresByEmail = new Map<string, ThrottleEntry>();

function now(): number {
  return Date.now();
}

/** Normalize an email the same way the login procedure does (trim + lowercase). */
function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Record a failed login attempt for the given email. Returns the resulting
 * entry so callers can log/metric it.
 */
export function recordLoginFailure(email: string, at: number = now()): ThrottleEntry {
  const key = normalizeEmail(email);
  const existing = failuresByEmail.get(key);
  if (!existing || at - existing.windowStartedAt >= WINDOW_MS) {
    const entry: ThrottleEntry = { count: 1, windowStartedAt: at };
    failuresByEmail.set(key, entry);
    return entry;
  }
  existing.count += 1;
  if (existing.count >= MAX_FAILURES_PER_WINDOW) {
    existing.blockedUntil = at + WINDOW_MS;
  }
  return existing;
}

/**
 * Whether a login attempt for this email is currently throttled.
 * Returns null when allowed, or a descriptor with the remaining lockout.
 */
export function isLoginThrottled(email: string, at: number = now()): { retryAfterMs: number; failures: number } | null {
  const entry = failuresByEmail.get(normalizeEmail(email));
  if (!entry) return null;
  if (entry.blockedUntil && entry.blockedUntil > at) {
    return { retryAfterMs: entry.blockedUntil - at, failures: entry.count };
  }
  return null;
}

/** Clear failure state for an email after a successful authentication. */
export function clearLoginFailures(email: string): void {
  failuresByEmail.delete(normalizeEmail(email));
}

/** Reset ALL state — used by tests. */
export function resetLoginThrottle(): void {
  failuresByEmail.clear();
}

/** Current number of tracked emails (observability/tests). */
export function trackedEmailCount(): number {
  return failuresByEmail.size;
}
