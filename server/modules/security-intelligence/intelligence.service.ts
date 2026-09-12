/**
 * SAMPRAAN security-intelligence rule engine (ADVISORY ONLY).
 *
 * Rules-first by design: every signal is derived from REAL audit_events rows
 * produced by actual operations (authorization denials, revoked-identity
 * activity, blockchain failures). Nothing here fabricates evidence and
 * NOTHING here participates in the authorization decision — the policy
 * engine and the smart contracts remain the only authorities. Risk scores
 * are advisory labels for investigators, never grants.
 *
 * Rules (each keyed deterministically so re-runs are idempotent per window):
 *  R1 REPEATED_DENIALS — an identity with >= 3 AUTHORIZATION_DENIED events
 *     within the recent window.
 *  R2 REVOKED_IDENTITY_ACTIVITY — audit rows referencing a REVOKED identity.
 *  R3 CHAIN_FAILURES — BLOCKCHAIN_TRANSACTION_FAILED / BLOCKCHAIN_ANCHOR_FAILED
 *     events (operational risk signal).
 */
import { createAuditEvent, createSecurityAlert, listAuditEvents, listIdentities } from "../../db";
import type { AuditEvent, Identity } from "../../../drizzle/schema";

const DENIAL_ALERT_THRESHOLD = 3;
const DEFAULT_WINDOW = 200;

export interface IntelligenceScanResult {
  scanned: number;
  created: number;
  suppressed: number;
  rules: { rule: string; identityId: string | null; count: number }[];
}

/** Only alert once per (rule, identity, day) — idempotent re-scans. */
function alertKey(rule: string, identityId: string | null, day: string) {
  return `${rule}:${identityId ?? "system"}:${day}`;
}

export class SecurityIntelligenceService {
  /**
   * Advisory risk level for an actor+action, derived from REAL audit events
   * in the recent window (LOOP 7). ADVISORY ONLY: the authorization engine
   * may use HIGH risk to ELEVATE a normally-allowed operation to CHALLENGE;
   * it can never use risk to GRANT anything (every DENY returns before the
   * risk check runs).
   */
  async assessRisk(input: { identityId: string | null; action: string; classification?: string }): Promise<"LOW" | "MEDIUM" | "HIGH"> {
    if (!input.identityId) return "LOW";
    try {
      const events = await listAuditEvents(DEFAULT_WINDOW).catch(() => [] as AuditEvent[]);
      let denials = 0;
      let stepUpFailures = 0;
      let challenges = 0;
      for (const event of events) {
        if (event.actorIdentityId !== input.identityId) continue;
        if (event.action === "AUTHORIZATION_DENIED") denials++;
        else if (event.action === "STEP_UP_FAILED") stepUpFailures++;
        else if (event.action === "AUTHORIZATION_CHALLENGED") challenges++;
      }
      const sensitive = input.classification === "HIGHLY_SENSITIVE" || input.classification === "CRITICAL";
      if (denials >= 3 || stepUpFailures >= 2) return "HIGH";
      if (sensitive && (challenges >= 2 || denials >= 1)) return "HIGH";
      if (denials >= 1 || challenges >= 1 || sensitive) return "MEDIUM";
      return "LOW";
    } catch {
      // Intelligence must never break authorization: absent data = LOW risk,
      // and LOW risk can only mean "no elevation" — never a grant.
      return "LOW";
    }
  }

  /**
   * Scan recent audit events and materialize advisory security_alerts rows.
   * Safe to call repeatedly (e.g. after every audit write) — duplicate alerts
   * within the same day are suppressed by a deterministic key stored in the
   * alert description.
   */
  async scan(input: { windowEvents?: number } = {}): Promise<IntelligenceScanResult> {
    const window = input.windowEvents ?? DEFAULT_WINDOW;
    const events = (await Promise.resolve(listAuditEvents(window)).catch(() => [] as AuditEvent[])) ?? ([] as AuditEvent[]);
    if (events.length === 0) {
      return { scanned: 0, created: 0, suppressed: 0, rules: [] };
    }
    const identities = await listIdentities().catch(() => [] as Identity[]);
    const byId = new Map(identities.map(identity => [identity.id, identity]));
    const revokedIds = new Set(identities.filter(i => i.status === "REVOKED" || i.status === "SUSPENDED").map(i => i.id));

    const day = new Date().toISOString().slice(0, 10);
    let created = 0;
    let suppressed = 0;
    const firedRules: IntelligenceScanResult["rules"] = [];

    // R1: repeated authorization denials per actor identity.
    const denialCounts = new Map<string, number>();
    for (const event of events) {
      if (event.action === "AUTHORIZATION_DENIED" && event.actorIdentityId) {
        denialCounts.set(event.actorIdentityId, (denialCounts.get(event.actorIdentityId) ?? 0) + 1);
      }
    }
    for (const [identityId, count] of denialCounts) {
      if (count < DENIAL_ALERT_THRESHOLD) continue;
      const key = alertKey("R1-REPEATED-DENIALS", identityId, day);
      const result = await this.upsertAlert({
        key,
        title: `Repeated authorization denials (${count} in recent window)`,
        severity: count >= 6 ? "HIGH" : "MEDIUM",
        status: "OPEN",
        identityId,
        assetId: null,
        description: `Advisory rule R1: identity ${byId.get(identityId)?.did ?? identityId} accumulated ${count} denied authorization requests in the last ${events.length} audit events. Pattern may indicate probing.`,
        riskScore: Math.min(95, 40 + count * 5),
      });
      if (result === "created") { created++; firedRules.push({ rule: "R1-REPEATED-DENIALS", identityId, count }); }
      else suppressed++;
    }

    // R2: revoked / suspended identity activity (attempted use after revocation).
    const revokedActivity = events.filter(
      event => event.actorIdentityId && revokedIds.has(event.actorIdentityId)
    );
    if (revokedActivity.length > 0) {
      const perIdentity = new Map<string, number>();
      for (const event of revokedActivity) {
        perIdentity.set(event.actorIdentityId!, (perIdentity.get(event.actorIdentityId!) ?? 0) + 1);
      }
      for (const [identityId, count] of perIdentity) {
        const key = alertKey("R2-REVOKED-ACTIVITY", identityId, day);
        const identity = byId.get(identityId);
        const result = await this.upsertAlert({
          key,
          title: `Activity from ${identity?.status === "SUSPENDED" ? "suspended" : "revoked"} identity`,
          severity: "HIGH",
          status: "OPEN",
          identityId,
          assetId: null,
          description: `Advisory rule R2: ${count} audit event(s) recorded under ${identity?.status.toLowerCase() ?? "non-active"} identity ${identity?.did ?? identityId}. The authorization boundary rejected its session; this signal is for investigators.`,
          riskScore: 80,
        });
        if (result === "created") { created++; firedRules.push({ rule: "R2-REVOKED-ACTIVITY", identityId, count }); }
        else suppressed++;
      }
    }

    // R3: blockchain operational failures.
    const chainFailures = events.filter(
      event => event.action === "BLOCKCHAIN_TRANSACTION_FAILED" || event.action === "BLOCKCHAIN_ANCHOR_FAILED"
    );
    if (chainFailures.length >= 1) {
      const key = alertKey("R3-CHAIN-FAILURES", null, day);
      const result = await this.upsertAlert({
        key,
        title: `Blockchain submission failures (${chainFailures.length})`,
        severity: chainFailures.length >= 3 ? "HIGH" : "MEDIUM",
        status: "OPEN",
        identityId: null,
        assetId: null,
        description: `Advisory rule R3: ${chainFailures.length} blockchain transaction/anchor failure(s) in the recent audit window. Anchoring is best-effort by design, but clusters of failures may indicate chain or operator-key issues.`,
        riskScore: chainFailures.length >= 3 ? 75 : 55,
      });
      if (result === "created") { created++; firedRules.push({ rule: "R3-CHAIN-FAILURES", identityId: null, count: chainFailures.length }); }
      else suppressed++;
    }

    // R4: repeated sensitive-asset access attempts — clusters of step-up
    // CHALLENGE decisions suggest probing of HIGHLY_SENSITIVE assets.
    const sensitiveAttempts = new Map<string, number>();
    for (const event of events) {
      if (event.action === "AUTHORIZATION_CHALLENGED" && event.actorIdentityId) {
        sensitiveAttempts.set(event.actorIdentityId, (sensitiveAttempts.get(event.actorIdentityId) ?? 0) + 1);
      }
    }
    for (const [identityId, count] of sensitiveAttempts) {
      if (count < 3) continue;
      const key = alertKey("R4-SENSITIVE-ATTEMPTS", identityId, day);
      const result = await this.upsertAlert({
        key,
        title: `Repeated sensitive-asset access attempts (${count})`,
        severity: count >= 6 ? "HIGH" : "MEDIUM",
        status: "OPEN",
        identityId,
        assetId: null,
        description: `Advisory rule R4: identity ${byId.get(identityId)?.did ?? identityId} triggered ${count} step-up CHALLENGE decisions in the recent window — possible probing of highly sensitive assets.`,
        riskScore: Math.min(90, 45 + count * 5),
      });
      if (result === "created") { created++; firedRules.push({ rule: "R4-SENSITIVE-ATTEMPTS", identityId, count }); }
      else suppressed++;
    }

    // R5: repeated step-up failures — invalid/expired/replayed step-up proofs.
    const stepUpFailures = new Map<string, number>();
    for (const event of events) {
      if (event.action === "STEP_UP_FAILED" && event.actorIdentityId) {
        stepUpFailures.set(event.actorIdentityId, (stepUpFailures.get(event.actorIdentityId) ?? 0) + 1);
      }
    }
    for (const [identityId, count] of stepUpFailures) {
      if (count < 2) continue;
      const key = alertKey("R5-STEP-UP-FAILURES", identityId, day);
      const result = await this.upsertAlert({
        key,
        title: `Repeated step-up verification failures (${count})`,
        severity: "HIGH",
        status: "OPEN",
        identityId,
        assetId: null,
        description: `Advisory rule R5: identity ${byId.get(identityId)?.did ?? identityId} failed server-verified step-up ${count} time(s) in the recent window — possible replay or key misuse.`,
        riskScore: Math.min(95, 60 + count * 8),
      });
      if (result === "created") { created++; firedRules.push({ rule: "R5-STEP-UP-FAILURES", identityId, count }); }
      else suppressed++;
    }

    // R6: abnormal transfer frequency — bursts of confirmed custody transfers.
    const transferCounts = new Map<string, number>();
    for (const event of events) {
      if (event.action === "ASSET_TRANSFERRED" && event.actorIdentityId) {
        transferCounts.set(event.actorIdentityId, (transferCounts.get(event.actorIdentityId) ?? 0) + 1);
      }
    }
    for (const [identityId, count] of transferCounts) {
      if (count < 5) continue;
      const key = alertKey("R6-TRANSFER-BURST", identityId, day);
      const result = await this.upsertAlert({
        key,
        title: `Unusual custody transfer activity (${count} transfers)`,
        severity: "MEDIUM",
        status: "OPEN",
        identityId,
        assetId: null,
        description: `Advisory rule R6: identity ${byId.get(identityId)?.did ?? identityId} confirmed ${count} on-chain custody transfers in the recent audit window — verify this operational burst is expected.`,
        riskScore: Math.min(85, 40 + count * 4),
      });
      if (result === "created") { created++; firedRules.push({ rule: "R6-TRANSFER-BURST", identityId, count }); }
      else suppressed++;
    }

    return { scanned: events.length, created, suppressed, rules: firedRules };
  }

  /**
   * Insert an alert unless an identical rule-fingerprint row already exists
   * today (the fingerprint lives in the description metadata). Returns
   * "created" | "suppressed" | "failed".
   */
  private async upsertAlert(input: {
    key: string;
    title: string;
    severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    status: "OPEN" | "INVESTIGATING" | "RESOLVED";
    identityId: string | null;
    assetId: string | null;
    description: string;
    riskScore: number;
  }): Promise<"created" | "suppressed" | "failed"> {
    try {
      const existing = await listSecurityAlertsIncludingResolved();
      const fingerprint = `rule-fingerprint:${input.key}`;
      const duplicate = existing.some(alert => (alert.description ?? "").includes(fingerprint));
      if (duplicate) return "suppressed";
      await createSecurityAlert({
        title: input.title,
        severity: input.severity,
        status: input.status,
        identityId: input.identityId,
        assetId: input.assetId,
        description: `${input.description} [${fingerprint}]`,
        riskScore: input.riskScore,
      });
      return "created";
    } catch (error) {
      console.error("[Intelligence] Failed to persist alert:", error);
      return "failed";
    }
  }
}

/** Local import indirection to keep this module's dependency surface explicit. */
import { listSecurityAlerts as listSecurityAlertsIncludingResolved } from "../../db";

export const securityIntelligenceService = new SecurityIntelligenceService();

/** Fire-and-forget scan used after audit writes (advisory, never blocking). */
export function scheduleIntelligenceScan(): void {
  void securityIntelligenceService.scan().catch(error => {
    console.error("[Intelligence] Background scan failed:", error);
  });
}

/** Explicit audit marker so the intelligence run itself is visible in the trail. */
export async function recordIntelligenceScanEvidence(result: IntelligenceScanResult): Promise<void> {
  if (result.created === 0 && result.rules.length === 0) return;
  await createAuditEvent({
    actorIdentityId: null,
    action: "SECURITY_INTELLIGENCE_SCAN",
    resourceType: "SECURITY",
    resourceId: "intelligence-engine",
    decision: "ALLOW",
    reason: `Advisory scan evaluated ${result.scanned} events; created ${result.created} alert(s), suppressed ${result.suppressed} duplicate(s)`,
    metadata: { source: "security-intelligence", rules: result.rules, advisory: true },
  }).catch(error => {
    console.error("[Intelligence] Failed to record scan evidence:", error);
  });
}
