import { describe, expect, it } from "vitest";
import {
  alertMetrics,
  assetMix,
  decisionLabel,
  decisionTone,
  formatClock,
  formatTimestamp,
  formatTxHash,
  initials,
  matchesAssetQuery,
  primaryAlert,
  severityTone,
  shortDid,
  statusTone,
  toAssetRows,
  toAuditRows,
  toDecisionRows,
  toEventFeed,
} from "./sampraan";
import type { Asset, AuditEvent, Identity } from "@shared/types";
import type { SecurityAlert } from "./sampraan";

const identity = (overrides: Partial<Identity> = {}): Identity => ({
  id: "identity-1",
  linkedUserId: null,
  displayName: "Aarav Mehta",
  organization: "SAMPRAAN DEMO ORGANIZATION",
  status: "ACTIVE",
  did: "did:demo:aarav-mehta",
  createdAt: new Date("2026-07-18T04:02:16Z"),
  updatedAt: new Date("2026-07-18T04:02:16Z"),
  revokedAt: null,
  ...overrides,
});

const auditEvent = (overrides: Partial<AuditEvent> = {}): AuditEvent => ({
  id: "event-1",
  actorIdentityId: "identity-1",
  action: "AUTHORIZATION_DENIED",
  resourceType: "ASSET",
  resourceId: "ASSET-DEMO-FIRMWARE-001",
  decision: "DENY",
  reason: "Role USER cannot TRANSFER HIGHLY_SENSITIVE asset",
  timestamp: new Date("2026-09-03T09:42:18Z"),
  transactionHash: null,
  blockNumber: null,
  metadata: { demo: true },
  source: "APPLICATION",
  ...overrides,
});

const asset = (overrides: Partial<Asset> = {}): Asset => ({
  id: "asset-1",
  assetId: "ASSET-DEMO-FIRMWARE-001",
  name: "Restricted Firmware Package",
  type: "FIRMWARE",
  classification: "HIGHLY_SENSITIVE",
  description: null,
  ownerIdentityId: "identity-1",
  custodianIdentityId: "identity-1",
  integrityHash: "sha256:demo",
  tokenId: null,
  status: "ACTIVE",
  createdAt: new Date("2026-09-03T09:41:52Z"),
  updatedAt: new Date("2026-09-03T09:41:52Z"),
  ...overrides,
});

const securityAlert = (overrides: Partial<SecurityAlert> = {}): SecurityAlert => ({
  id: "alert-1",
  title: "Suspicious Asset Access Pattern",
  severity: "HIGH",
  status: "OPEN",
  identityId: "identity-1",
  assetId: "asset-1",
  description: "Fictional demo alert.",
  riskScore: 87,
  createdAt: new Date("2026-09-03T09:47:00Z"),
  resolvedAt: null,
  ...overrides,
});

describe("decision mapping", () => {
  it("maps decision enums to workspace tones and labels", () => {
    expect(decisionTone("ALLOW")).toBe("mint");
    expect(decisionTone("DENY")).toBe("red");
    expect(decisionTone("CHALLENGE")).toBe("amber");
    expect(decisionTone(null)).toBe("muted");
    expect(decisionLabel("ALLOW")).toBe("ALLOWED");
    expect(decisionLabel("DENY")).toBe("DENIED");
    expect(decisionLabel("CHALLENGE")).toBe("CHALLENGE");
    expect(decisionLabel(undefined)).toBe("—");
  });

  it("maps lifecycle statuses and severities to tones", () => {
    expect(statusTone("ACTIVE")).toBe("mint");
    expect(statusTone("PENDING")).toBe("amber");
    expect(statusTone("REVOKED")).toBe("red");
    expect(statusTone(undefined)).toBe("muted");
    expect(severityTone("CRITICAL")).toBe("red");
    expect(severityTone("MEDIUM")).toBe("amber");
    expect(severityTone("LOW")).toBe("muted");
  });
});

describe("formatting", () => {
  it("formats clock times and full timestamps", () => {
    const date = new Date("2026-09-03T09:42:18Z");
    expect(formatClock(date)).toBe(date.toLocaleTimeString([], { hour12: false }));
    expect(formatClock(null)).toBe("—");
    expect(formatTimestamp(null)).toBe("—");
  });

  it("shortens DIDs and keeps short DIDs intact", () => {
    expect(shortDid("did:ethr:0x7a93abcdefc21")).toBe("did:ethr:0…fc21");
    expect(shortDid("did:demo:aarav-mehta")).toBe("did:demo:aarav-mehta");
    expect(shortDid(null)).toBe("—");
    expect(shortDid("short")).toBe("short");
  });

  it("derives initials from names and emails", () => {
    expect(initials("Arjun Singh")).toBe("AS");
    expect(initials("priya.dev@bel.gov.in")).toBe("PD");
    expect(initials(null)).toBe("OP");
    expect(initials("  ")).toBe("OP");
  });

  it("renders tx cells with and without chain anchors", () => {
    expect(formatTxHash({ transactionHash: "0x7f3abcdefc921", blockNumber: 18492201 })).toContain("#18,492,201");
    expect(formatTxHash({ transactionHash: null, blockNumber: null })).toBe("NOT ANCHORED");
    expect(formatTxHash({ transactionHash: null, blockNumber: 42 })).toBe("BLOCK #42");
  });
});

describe("audit row mapping", () => {
  it("resolves actors, decisions, and tx anchors through the identity map", () => {
    const rows = toAuditRows([auditEvent()], [identity()]);
    expect(rows).toHaveLength(1);
    expect(rows[0].actor).toBe("Aarav Mehta");
    expect(rows[0].did).toBe("did:demo:aarav-mehta");
    expect(rows[0].decision).toBe("DENIED");
    expect(rows[0].decisionTone).toBe("red");
    expect(rows[0].tx).toBe("NOT ANCHORED");
    expect(rows[0].resource).toBe("ASSET-DEMO-FIRMWARE-001");
  });

  it("marks unattributed actors without crashing", () => {
    const rows = toAuditRows([auditEvent({ actorIdentityId: null, id: "event-2" })], []);
    expect(rows[0].actor).toBe("Unattributed actor");
    expect(rows[0].did).toBe("—");
  });

  it("feeds the decisions panel from authorization events only", () => {
    const events = [auditEvent(), auditEvent({ id: "event-3", action: "IDENTITY_CREATED", decision: null })];
    const decisions = toDecisionRows(events, [identity()]);
    expect(decisions).toHaveLength(1);
    expect(decisions[0].action).toBe("DENIED");
    expect(decisions[0].asset).toBe("ASSET-DEMO-FIRMWARE-001");
  });

  it("feeds the security-event panel with readable labels", () => {
    const feed = toEventFeed([auditEvent({ id: "event-4" })]);
    expect(feed[0].label).toBe("AUTHORIZATION DENIED");
    expect(feed[0].meta).toContain("ASSET-DEMO-FIRMWARE-001");
  });
});

describe("asset registry mapping", () => {
  it("maps assets with resolved custodians and status tones", () => {
    const rows = toAssetRows([asset()], [identity({ displayName: "Ananya Rao" })]);
    expect(rows[0].custodian).toBe("Ananya Rao");
    expect(rows[0].statusTone).toBe("mint");
    expect(rows[0].name).toBe("Restricted Firmware Package");
  });

  it("falls back to a neutral custodian label when the identity is missing", () => {
    const rows = toAssetRows([asset()], []);
    expect(rows[0].custodian).toBe("CUSTODIAN ON RECORD");
  });

  it("buckets the asset mix by type keyword", () => {
    const mix = assetMix([
      asset(),
      asset({ id: "asset-2", assetId: "TEST-INST-08", type: "INSTRUMENT", name: "Environmental Test Instrument" }),
      asset({ id: "asset-3", assetId: "KEY-01", type: "KEY MATERIAL", name: "Signing Key Material" }),
    ]);
    expect(mix.find(bucket => bucket.label === "FIRMWARE")?.count).toBe(1);
    expect(mix.find(bucket => bucket.label === "INSTRUMENTS")?.count).toBe(1);
    expect(mix.find(bucket => bucket.label === "CRYPTO MATERIAL")?.count).toBe(1);
    expect(mix.reduce((sum, bucket) => sum + bucket.count, 0)).toBe(3);
  });

  it("matches registry search queries across fields", () => {
    const row = toAssetRows([asset()], [identity()])[0];
    expect(matchesAssetQuery(row, "firmware")).toBe(true);
    expect(matchesAssetQuery(row, "aarav")).toBe(true);
    expect(matchesAssetQuery(row, "highly")).toBe(true);
    expect(matchesAssetQuery(row, "nonexistent")).toBe(false);
    expect(matchesAssetQuery(row, "")).toBe(true);
  });
});

describe("alert aggregation", () => {
  it("derives intelligence metrics from the alert registry", () => {
    const metrics = alertMetrics([
      securityAlert(),
      securityAlert({ id: "alert-2", severity: "MEDIUM", status: "INVESTIGATING", riskScore: 40, identityId: "identity-2" }),
      securityAlert({ id: "alert-3", severity: "HIGH", status: "RESOLVED", riskScore: 30 }),
    ]);
    expect(metrics.openCount).toBe(1);
    expect(metrics.investigatingCount).toBe(1);
    expect(metrics.maxRisk).toBe(87);
    expect(metrics.highRiskIdentities).toBe(1);
    expect(metrics.criticalCount).toBe(0);
  });

  it("reports a quiet registry safely", () => {
    expect(alertMetrics([])).toEqual({ openCount: 0, investigatingCount: 0, maxRisk: null, highRiskIdentities: 0, criticalCount: 0 });
    expect(alertMetrics(undefined).maxRisk).toBeNull();
  });

  it("prefers the first open alert as the primary investigation", () => {
    const alerts = [
      securityAlert({ id: "alert-resolved", status: "RESOLVED" }),
      securityAlert({ id: "alert-open", status: "OPEN", title: "Latest open signal" }),
    ];
    expect(primaryAlert(alerts)?.id).toBe("alert-open");
    expect(primaryAlert([])).toBeNull();
    expect(primaryAlert([securityAlert({ status: "RESOLVED" })])?.status).toBe("RESOLVED");
  });
});
