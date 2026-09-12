import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";

/**
 * SAMPRAAN data hooks.
 *
 * Strategy: when a session exists, read through the protected tRPC procedures
 * (identities.list, assets.list, audit.list, alerts.list) — the backend stays
 * the authorization boundary. When there is no session (the SIH demo workspace),
 * fall back to the public dev-only demo.* procedures so the workspace keeps
 * working in Demo Mode. Demo procedures are dev-only by design; errors are
 * tolerated and surfaces render their demo fallback content.
 *
 * No new API surface is invented here — every query maps 1:1 to an existing
 * procedure in server/routers.ts.
 *
 * The demo.* fallback procedures are DEVELOPMENT-ONLY on the server (they
 * throw FORBIDDEN outside development). A production build must not keep
 * firing them every refetch interval for unauthenticated visitors — that
 * only produces console errors. Gate the demo queries on the Vite build
 * mode, which mirrors the server's NODE_ENV check: `vite dev` serves a
 * development client against a development server; `vite build` output is
 * served by a production server that correctly refuses demo data.
 */

/** True when this client build runs in development mode (Vite dev server). */
const isDevBuild = import.meta.env.DEV;

const REFETCH_MS = 30_000;
const STALE_MS = 15_000;

/**
 * Shared shape for every domain hook. `source` lets surfaces distinguish
 * "live backend rows" from "unavailable — render demo fallback".
 */
export type SampraanQueryResult<T> = {
  data: T | undefined;
  isLoading: boolean;
  isFetching: boolean;
  error: unknown;
  /** "live" = the active backend query succeeded (protected or demo procedure). "unavailable" = render demo fallback content. */
  source: "live" | "unavailable";
};

function toResult<T>(query: { data: T | undefined; isLoading: boolean; isFetching: boolean; error: unknown; isError: boolean; isSuccess: boolean }): SampraanQueryResult<T> {
  // "live" means the active backend query succeeded — the surface should
  // render real rows. A failed or disabled read keeps surfaces on their demo
  // fallback content while the error is surfaced explicitly.
  return {
    data: query.data,
    isLoading: query.isLoading,
    isFetching: query.isFetching,
    error: query.isError ? query.error : undefined,
    source: query.isSuccess ? "live" : "unavailable",
  };
}

/** Identity registry: protected identities.list, demo.identities fallback. */
export function useIdentities() {
  const { isAuthenticated } = useAuth();
  const live = trpc.identities.list.useQuery(undefined, {
    enabled: isAuthenticated,
    staleTime: STALE_MS,
    refetchInterval: REFETCH_MS,
    retry: false,
  });
  const demo = trpc.demo.identities.useQuery(undefined, {
    enabled: !isAuthenticated && isDevBuild,
    staleTime: STALE_MS,
    retry: false,
  });
  const query = isAuthenticated ? live : demo;
  const result = toResult(query);
  // Normalize the union: the protected procedure returns identities WITH
  // roles; demo rows don't. The UI can rely on `roles` always being an array.
  return {
    ...result,
    data: result.data as
      | (import("@shared/types").Identity & { roles?: string[] })[]
      | undefined,
  };
}

/** Asset registry: protected assets.list, demo.assets fallback. */
export function useAssets() {
  const { isAuthenticated } = useAuth();
  const live = trpc.assets.list.useQuery(undefined, {
    enabled: isAuthenticated,
    staleTime: STALE_MS,
    refetchInterval: REFETCH_MS,
    retry: false,
  });
  const demo = trpc.demo.assets.useQuery(undefined, {
    enabled: !isAuthenticated && isDevBuild,
    staleTime: STALE_MS,
    retry: false,
  });
  const query = isAuthenticated ? live : demo;
  return toResult(query);
}

/** Audit evidence stream: protected audit.list, demo.audit fallback. */
export function useAuditEvents() {
  const { isAuthenticated } = useAuth();
  const live = trpc.audit.list.useQuery({ limit: 200 }, {
    enabled: isAuthenticated,
    staleTime: STALE_MS,
    refetchInterval: REFETCH_MS,
    retry: false,
  });
  const demo = trpc.demo.audit.useQuery(undefined, {
    enabled: !isAuthenticated && isDevBuild,
    staleTime: STALE_MS,
    retry: false,
  });
  const query = isAuthenticated ? live : demo;
  return toResult(query);
}

/** Security alerts: protected alerts.list, demo.alerts fallback. */
export function useSecurityAlerts() {
  const { isAuthenticated } = useAuth();
  const live = trpc.alerts.list.useQuery(undefined, {
    enabled: isAuthenticated,
    staleTime: STALE_MS,
    refetchInterval: REFETCH_MS,
    retry: false,
  });
  const demo = trpc.demo.alerts.useQuery(undefined, {
    enabled: !isAuthenticated && isDevBuild,
    staleTime: STALE_MS,
    retry: false,
  });
  const query = isAuthenticated ? live : demo;
  return toResult(query);
}

/** Public observatory summary (counts + blockchain status). */
export function useObservatory() {
  const query = trpc.observatory.useQuery(undefined, {
    refetchInterval: REFETCH_MS,
    staleTime: STALE_MS,
    retry: 1,
  });
  return toResult(query);
}

/** Public blockchain network status (mock chain: connected=false, mode=MOCK). */
export function useBlockchainStatus() {
  const query = trpc.blockchain.status.useQuery(undefined, {
    refetchInterval: REFETCH_MS,
    staleTime: STALE_MS,
    retry: 1,
  });
  return toResult(query);
}
