import type { CookieOptions, Request } from "express";

/**
 * Session cookie policy.
 *
 * SameSite=Lax is the secure default: the session cookie is sent on
 * same-site requests and top-level navigations, but NOT on cross-site
 * POSTs, which blocks the classic CSRF vector (a foreign site posting to
 * /api/trpc with the victim cookie). Lax keeps normal OAuth-redirect
 * top-level GET navigation working.
 *
 * SameSite=None is reserved for the one-time OAuth state cookie, which
 * genuinely must survive a cross-site redirect round-trip to the identity
 * provider (see oauth.ts); the session cookie never needs it.
 *
 * The secure flag follows the transport: true on https or behind a proxy
 * reporting https via x-forwarded-proto.
 */
export function getSessionCookieOptions(
  req: Request
): Pick<CookieOptions, "domain" | "httpOnly" | "path" | "sameSite" | "secure"> {
  return {
    httpOnly: true,
    path: "/",
    sameSite: "lax",
    secure: isSecureRequest(req),
  };
}

function isSecureRequest(req: Request) {
  if (req.protocol === "https") return true;

  const forwardedProto = req.headers["x-forwarded-proto"];
  if (!forwardedProto) return false;

  const protoList = Array.isArray(forwardedProto)
    ? forwardedProto
    : forwardedProto.split(",");

  return protoList.some(proto => proto.trim().toLowerCase() === "https");
}
