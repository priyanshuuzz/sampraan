/**
 * Listen-port resolution for the SAMPRAAN server.
 *
 * BUG-AUDIT-1 (reproduced live): `parseInt(process.env.PORT || "3000")`
 * accepted nonsense values — an inherited `PORT=0` (observed in a real
 * environment) made Express bind an EPHEMERAL port while logging
 * "Server running on http://localhost:0/". In production the healthcheck
 * targets the configured port, so the container would report unhealthy
 * forever while the process looks alive.
 *
 * Rule: a PORT value that is present but not an integer in [1, 65535] is a
 * configuration ERROR, never silently coerced. Empty/unset returns null so
 * the caller can apply its default.
 */
export function parseListenPort(raw: string | undefined | null): number | null {
  if (raw === undefined || raw === null) return null;
  const trimmed = raw.trim();
  if (trimmed === "") return null;
  // Plain decimal digits ONLY: Number() would silently accept "0x50" (80),
  // "1e3" (1000) or "Infinity" — surprising coercions have no place in a
  // deployment-critical value.
  if (!/^\d+$/.test(trimmed)) return null;
  const port = Number(trimmed);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return port;
}
