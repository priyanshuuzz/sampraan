import type { Asset, AuditEvent, Identity } from "@shared/types";

/**
 * SAMPRAAN frontend display helpers.
 *
 * Pure mapping/formatting only — no React, no network. Shared by the workspace
 * pages so live backend rows and demo fallback rows render through the exact
 * same display contract. Types come from the Drizzle schema via @shared/types
 * (the same types the tRPC procedures return through superjson).
 */

export type Tone = "mint" | "amber" | "red" | "muted";

/**
 * Client-side view of the security_alerts rows returned by alerts.list /
 * demo.alerts. The server schema type is not re-exported through @shared/types,
 * so this mirrors the drizzle securityAlerts table select shape exactly
 * (drizzle/schema.ts → securityAlerts) without touching backend code.
 */
export interface SecurityAlert {
  id: string;
  title: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: "OPEN" | "INVESTIGATING" | "RESOLVED";
  identityId: string | null;
  assetId: string | null;
  description: string;
  riskScore: number | null;
  createdAt: Date;
  resolvedAt: Date | null;
}

/** Authorization / audit decision enum → display tone. */
export function decisionTone(decision: string | null | undefined): Tone {
  switch (decision) {
    case "ALLOW":
      return "mint";
    case "DENY":
      return "red";
    case "CHALLENGE":
      return "amber";
    default:
      return "muted";
  }
}

/** Authorization / audit decision enum → workspace label (ALLOWED / DENIED / CHALLENGE). */
export function decisionLabel(decision: string | null | undefined): string {
  switch (decision) {
    case "ALLOW":
      return "ALLOWED";
    case "DENY":
      return "DENIED";
    case "CHALLENGE":
      return "CHALLENGE";
    default:
      return "—";
  }
}

/** Asset / identity lifecycle status → display tone. */
export function statusTone(status: string | null | undefined): Tone {
  switch (status) {
    case "ACTIVE":
      return "mint";
    case "PENDING":
    case "SUSPENDED":
      return "amber";
    case "REVOKED":
      return "red";
    default:
      return "muted";
  }
}

/** Security alert severity → display tone. */
export function severityTone(severity: string | null | undefined): Tone {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return "red";
    case "MEDIUM":
      return "amber";
    default:
      return "muted";
  }
}

/** Security alert status → display tone (open/investigating stay elevated, resolved settles). */
export function alertStatusTone(status: string | null | undefined): Tone {
  switch (status) {
    case "OPEN":
      return "red";
    case "INVESTIGATING":
      return "amber";
    case "RESOLVED":
      return "mint";
    default:
      return "muted";
  }
}

/** Compact clock time used across tables and timelines (09:42:18). */
export function formatClock(value: Date | string | null | undefined): string {
  if (value === null || value === undefined) return "—";
  const date = typeof value === "string" ? new Date(value) : value;
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleTimeString([], { hour12: false });
}

/** Full timestamp for title tooltips / evidence export context. */
export function formatTimestamp(value: Date | string | null | undefined): string {
  if (value === null || value === undefined) return "—";
  const date = typeof value === "string" ? new Date(value) : value;
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString([], { hour12: false });
}

/** Shorten a DID for dense tables: did:ethr:0x7a93…c21 → did:ethr:0x7a…c21. */
export function shortDid(did: string | null | undefined, keep = 10): string {
  if (!did) return "—";
  if (did.length <= keep * 2 + 1) return did;
  return `${did.slice(0, keep)}…${did.slice(-4)}`;
}

/** Avatar / side-user initials from a display name or email. */
export function initials(name: string | null | undefined, fallback = "OP"): string {
  if (!name) return fallback;
  const parts = name.trim().split(/[\s@._-]+/).filter(Boolean);
  if (parts.length === 0) return fallback;
  const first = parts[0]?.[0] ?? "";
  const second = parts.length > 1 ? (parts[1]?.[0] ?? "") : (parts[0]?.[1] ?? "");
  return (first + second).toUpperCase() || fallback;
}

/** Tx hash / block cell for audit rows; keeps monospace density when data is absent. */
export function formatTxHash(event: Pick<AuditEvent, "transactionHash" | "blockNumber">): string {
  if (event.transactionHash) {
    const block = event.blockNumber ? ` / #${event.blockNumber.toLocaleString()}` : "";
    return `${shortDid(event.transactionHash, 8)}${block}`;
  }
  return event.blockNumber ? `BLOCK #${event.blockNumber.toLocaleString()}` : "NOT ANCHORED";
}

/** Map actor identity id → identity record for audit/alert actor resolution. */
export function identityMap(identities: Identity[] | undefined | null): Map<string, Identity> {
  const map = new Map<string, Identity>();
  for (const identity of identities ?? []) map.set(identity.id, identity);
  return map;
}

export interface AuditDisplayRow {
  key: string;
  time: string;
  fullTime: string;
  actor: string;
  did: string;
  action: string;
  resource: string;
  decision: string;
  decisionTone: Tone;
  tx: string;
}

/** Normalize audit events into the workspace table contract. */
export function toAuditRows(events: AuditEvent[] | undefined | null, identities: Identity[] | undefined | null): AuditDisplayRow[] {
  const byId = identityMap(identities);
  return (events ?? []).map((event, index) => {
    const actor = event.actorIdentityId ? byId.get(event.actorIdentityId) : undefined;
    return {
      key: event.id ?? `${event.timestamp?.toString?.() ?? index}-${index}`,
      time: formatClock(event.timestamp),
      fullTime: formatTimestamp(event.timestamp),
      actor: actor?.displayName ?? "Unattributed actor",
      did: actor ? shortDid(actor.did) : "—",
      action: event.action,
      resource: event.resourceId ?? event.resourceType,
      decision: decisionLabel(event.decision),
      decisionTone: decisionTone(event.decision),
      tx: formatTxHash(event),
    };
  });
}

/** Authorization-style decision row for the Command Center decisions panel. */
export interface DecisionDisplayRow {
  key: string;
  time: string;
  did: string;
  action: string;
  asset: string;
  decision: string;
  tone: Tone;
}

export function toDecisionRows(events: AuditEvent[] | undefined | null, identities: Identity[] | undefined | null, limit = 4): DecisionDisplayRow[] {
  const byId = identityMap(identities);
  return (events ?? [])
    .filter(event => event.action.startsWith("AUTHORIZATION"))
    .slice(0, limit)
    .map((event, index) => {
      const actor = event.actorIdentityId ? byId.get(event.actorIdentityId) : undefined;
      return {
        key: event.id ?? `${index}`,
        time: formatClock(event.timestamp),
        did: actor ? shortDid(actor.did) : "did:—",
        action: event.action.replace("AUTHORIZATION_", ""),
        asset: event.resourceId ?? event.resourceType,
        decision: decisionLabel(event.decision),
        tone: decisionTone(event.decision),
      };
    });
}

/** Live security-event feed rows for the Command Center events panel. */
export interface EventFeedRow {
  key: string;
  label: string;
  meta: string;
  time: string;
  tone: Tone;
}

export function toEventFeed(events: AuditEvent[] | undefined | null, limit = 4): EventFeedRow[] {
  return (events ?? [])
    .slice(0, limit)
    .map((event, index) => ({
      key: event.id ?? `${index}`,
      label: event.action.replace(/_/g, " "),
      meta: [event.resourceId ?? event.resourceType, event.decision ?? "RECORDED"].filter(Boolean).join(" / "),
      time: formatClock(event.timestamp),
      tone: decisionTone(event.decision),
    }));
}

/** Aggregate alert metrics for the Security Intelligence page without inventing new APIs. */
export interface AlertMetrics {
  openCount: number;
  investigatingCount: number;
  maxRisk: number | null;
  highRiskIdentities: number;
  criticalCount: number;
}

export function alertMetrics(alerts: SecurityAlert[] | undefined | null): AlertMetrics {
  const list = alerts ?? [];
  const open = list.filter(alert => alert.status === "OPEN");
  const investigating = list.filter(alert => alert.status === "INVESTIGATING");
  const risks = open.map(alert => alert.riskScore ?? 0);
  const highRiskIdentities = new Set(
    open
      .filter(alert => alert.severity === "HIGH" || alert.severity === "CRITICAL")
      .map(alert => alert.identityId ?? alert.id)
  );
  return {
    openCount: open.length,
    investigatingCount: investigating.length,
    maxRisk: risks.length ? Math.max(...risks) : null,
    highRiskIdentities: highRiskIdentities.size,
    criticalCount: list.filter(alert => alert.severity === "CRITICAL" && alert.status !== "RESOLVED").length,
  };
}

/** First open alert for the Alerts investigation hero, falling back to the newest alert. */
export function primaryAlert(alerts: SecurityAlert[] | undefined | null): SecurityAlert | null {
  const list = alerts ?? [];
  return list.find(alert => alert.status === "OPEN") ?? list[0] ?? null;
}

export interface AssetDisplayRow {
  key: string;
  assetId: string;
  name: string;
  classification: string;
  custodian: string;
  status: string;
  statusTone: Tone;
  time: string;
}

/** Normalize assets for the registry table, resolving custodian identity ids to names. */
export function toAssetRows(assets: Asset[] | undefined | null, identities: Identity[] | undefined | null): AssetDisplayRow[] {
  const byId = identityMap(identities);
  return (assets ?? []).map(asset => {
    const custodian = byId.get(asset.custodianIdentityId);
    return {
      key: asset.id ?? asset.assetId,
      assetId: asset.assetId,
      name: asset.name,
      classification: asset.classification,
      custodian: custodian?.displayName ?? "CUSTODIAN ON RECORD",
      status: asset.status,
      statusTone: statusTone(asset.status),
      time: formatClock(asset.createdAt),
    };
  });
}

/** Asset mix for the Command Center asset activity panel, bucketed by asset type keyword. */
export function assetMix(assets: Asset[] | undefined | null): { label: string; count: number; ratio: number }[] {
  const list = assets ?? [];
  const buckets: { label: string; count: number }[] = [
    { label: "FIRMWARE", count: 0 },
    { label: "INSTRUMENTS", count: 0 },
    { label: "DOCUMENTS", count: 0 },
    { label: "CRYPTO MATERIAL", count: 0 },
  ];
  const keywords: [string, number][] = [
    ["FIRMWARE", 0],
    ["INSTRUMENT", 1],
    ["DOC", 2],
    ["KEY", 3],
    ["CRYPTO", 3],
  ];
  for (const asset of list) {
    const type = `${asset.type} ${asset.name}`.toUpperCase();
    const bucket = keywords.find(([keyword]) => type.includes(keyword));
    if (bucket) buckets[bucket[1]].count += 1;
  }
  const counted = buckets.reduce((sum, bucket) => sum + bucket.count, 0);
  const total = Math.max(list.length, counted, 1);
  return buckets.map(bucket => ({ label: bucket.label, count: bucket.count, ratio: Math.round((bucket.count / total) * 100) }));
}

/** Filter text for the asset registry search field. */
export function matchesAssetQuery(asset: AssetDisplayRow, query: string): boolean {
  const q = query.trim().toUpperCase();
  if (!q) return true;
  return [asset.name, asset.assetId, asset.classification, asset.custodian, asset.status].some(value => value.toUpperCase().includes(q));
}
