/**
 * SAMPRAAN CRYPTOGRAPHIC ASSURANCE POLICY.
 *
 * Decides — DETERMINISTICALLY and with machine-readable reason codes — how much
 * cryptographic assurance an operation must present before it is allowed to
 * proceed:
 *
 *   BASELINE          session-bound ECDSA only (ordinary, low-risk work)
 *   ELEVATED          ECDSA + a server-verified step-up for this purpose
 *   QUANTUM_HARDENED  ECDSA + ML-DSA-65 (dual signature over one payload)
 *
 * Three properties are deliberate and must not be relaxed:
 *
 *  1. NO USER SELECTION. The caller never names an algorithm. The engine maps
 *     (operation, classification, risk, role, custody, approval, step-up) onto a
 *     level, and the level fixes the algorithm set. `ml-dsa.ts` and the
 *     verification service accept exactly the algorithms this module returns.
 *  2. DETERMINISTIC + EXPLAINABLE. The same inputs always produce the same
 *     level and the same ordered reason codes. There is no randomness, no
 *     clock, no database read and no "AI" here — it is a pure function, so it
 *     is reproducible in an audit and unit-testable in isolation.
 *  3. FAIL-CLOSED ON UNKNOWN INPUT. An unrecognised classification, operation
 *     or risk value contributes its WORST-case weight rather than being
 *     ignored, so a new enum value can never silently lower assurance.
 *
 * This module is the ASSURANCE half of the two-layer model: the existing
 * AuthorizationService still decides ALLOW / DENY / CHALLENGE. This engine only
 * decides HOW STRONGLY an allowed operation must be cryptographically proven.
 * It can never grant access — it has no ALLOW output at all.
 */

/** How strongly an operation must be cryptographically proven. */
export type AssuranceLevel = "BASELINE" | "ELEVATED" | "QUANTUM_HARDENED";

/** Signature algorithms the platform understands. Never client-selected. */
export type SignatureAlgorithm = "ECDSA_SECP256K1" | "ML_DSA_65";

export const ALGORITHM_BY_LEVEL: Record<AssuranceLevel, readonly SignatureAlgorithm[]> = {
  BASELINE: ["ECDSA_SECP256K1"],
  ELEVATED: ["ECDSA_SECP256K1"],
  QUANTUM_HARDENED: ["ECDSA_SECP256K1", "ML_DSA_65"],
};

/** Ordered, stable reason codes (the order below is the emitted order). */
export const ASSURANCE_REASON_CODES = [
  "OP_BASELINE",
  "OP_ELEVATED_RISK",
  "OP_ADMINISTRATIVE",
  "OP_IRREVERSIBLE",
  "CLASSIFICATION_UNKNOWN",
  "CLASSIFICATION_HIGHLY_SENSITIVE",
  "CLASSIFICATION_CRITICAL",
  "RISK_MEDIUM",
  "RISK_HIGH",
  "RISK_CRITICAL",
  "ROLE_ADMIN_BLAST_RADIUS",
  "ROLE_AUDITOR_READ_ONLY",
  "CUSTODY_MISMATCH",
  "CUSTODY_NOT_CUSTODIAN",
  "APPROVAL_MISSING",
  "APPROVAL_REJECTED",
  "STEP_UP_NOT_SATISFIED",
  "PQC_POLICY_MANDATED",
  "PLATFORM_FLOOR",
] as const;
export type AssuranceReasonCode = (typeof ASSURANCE_REASON_CODES)[number];

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type CustodyRelation =
  /** Actor currently holds custody of the resource. */
  | "CUSTODIAN"
  /** Actor owns but does not currently hold custody. */
  | "OWNER"
  /** Actor has neither ownership nor custody. */
  | "NONE"
  /** Privileged administrative override (never granted by the client). */
  | "ADMIN_OVERRIDE"
  | "NOT_APPLICABLE";

export type ApprovalState = "NOT_REQUIRED" | "PENDING" | "APPROVED" | "REJECTED" | "EXECUTED";

/**
 * Operation classes the engine understands. Kept as a closed union so an
 * unknown operation is a TYPE error rather than a silent baseline.
 */
export type AssuranceOperation =
  | "ASSET_VIEW"
  | "CONTENT_ACCESS"
  | "CONTENT_UPLOAD"
  | "ASSET_MINT"
  | "ASSET_ASSIGN"
  | "ASSET_TRANSFER"
  | "ASSET_FORCE_TRANSFER"
  | "ASSET_BURN"
  | "ASSET_STATUS_CHANGE"
  | "IDENTITY_VERIFY"
  | "IDENTITY_STATUS_CHANGE"
  | "IDENTITY_ROLE_CHANGE"
  | "IDENTITY_ROLE_ADMIN"
  | "DID_DOCUMENT_UPDATE"
  | "DID_KEY_ROTATE"
  | "DID_KEY_REVOKE"
  | "KEY_RECOVERY_REQUEST"
  | "KEY_RECOVERY_APPROVE"
  | "KEY_RECOVERY_EXECUTE"
  | "GOVERNANCE_PROPOSAL"
  | "GOVERNANCE_APPROVE"
  | "GOVERNANCE_EXECUTE"
  | "GOVERNANCE_CANCEL"
  | "GOVERNANCE_CONFIG"
  | "PAUSE_REGISTRY"
  | "UNPAUSE_REGISTRY"
  | "DISPUTE_RESOLVE"
  | "AUDIT_REPORT_COMMIT"
  | "CONSENT_GRANT";

/** Operations that are administrative in nature (role/config authority). */
const ADMINISTRATIVE_OPERATIONS: ReadonlySet<AssuranceOperation> = new Set([
  "IDENTITY_ROLE_CHANGE",
  "IDENTITY_ROLE_ADMIN",
  "GOVERNANCE_CONFIG",
  "GOVERNANCE_PROPOSAL",
  "GOVERNANCE_APPROVE",
  "GOVERNANCE_EXECUTE",
  "GOVERNANCE_CANCEL",
  "PAUSE_REGISTRY",
  "UNPAUSE_REGISTRY",
]);

/**
 * Operations whose effect cannot be undone by a later operation — burning an
 * NFT, force-moving custody, or terminally deactivating an identity. These
 * carry a hard floor: they can never be BASELINE.
 */
const IRREVERSIBLE_OPERATIONS: ReadonlySet<AssuranceOperation> = new Set([
  "ASSET_BURN",
  "ASSET_FORCE_TRANSFER",
  "IDENTITY_STATUS_CHANGE",
  "KEY_RECOVERY_EXECUTE",
  "DID_KEY_REVOKE",
]);

/**
 * Operations for which a POST-QUANTUM signature is mandated by platform
 * policy regardless of the additive score.
 *
 * Rationale: these operations change WHO CAN DO THINGS (role/identity
 * authority), destroy evidence (burn), or move custody by force. A future
 * quantum adversary that recovered a secp256k1 key could otherwise
 * retroactively forge the audit record for exactly these actions, and no
 * subsequent action could undo the forgery. Requiring ML-DSA-65 makes the
 * archived evidence unforgeable.
 *
 * Pause/unpause is deliberately NOT in this set: it is immediately reversible,
 * so it sits at ELEVATED (step-up) without forcing every operator to hold a
 * post-quantum key just to pause a registry.
 */
const QUANTUM_MANDATED_OPERATIONS: ReadonlySet<AssuranceOperation> = new Set([
  "ASSET_BURN",
  "ASSET_FORCE_TRANSFER",
  "IDENTITY_ROLE_ADMIN",
  "GOVERNANCE_CONFIG",
  "IDENTITY_STATUS_CHANGE",
  "KEY_RECOVERY_EXECUTE",
]);

/** Risk weights are additive, non-negative, and bounded by construction. */
const OPERATION_WEIGHT: Partial<Record<AssuranceOperation, number>> = {
  ASSET_BURN: 60,
  ASSET_FORCE_TRANSFER: 60,
  KEY_RECOVERY_EXECUTE: 55,
  IDENTITY_ROLE_ADMIN: 55,
  IDENTITY_ROLE_CHANGE: 45,
  GOVERNANCE_CONFIG: 55,
  GOVERNANCE_EXECUTE: 45,
  GOVERNANCE_PROPOSAL: 35,
  GOVERNANCE_APPROVE: 35,
  GOVERNANCE_CANCEL: 30,
  DID_KEY_REVOKE: 45,
  IDENTITY_STATUS_CHANGE: 45,
  KEY_RECOVERY_APPROVE: 35,
  KEY_RECOVERY_REQUEST: 30,
  DID_KEY_ROTATE: 30,
  DID_DOCUMENT_UPDATE: 25,
  ASSET_TRANSFER: 25,
  ASSET_ASSIGN: 25,
  ASSET_MINT: 25,
  ASSET_STATUS_CHANGE: 30,
  IDENTITY_VERIFY: 20,
  DISPUTE_RESOLVE: 25,
  AUDIT_REPORT_COMMIT: 15,
  PAUSE_REGISTRY: 30,
  UNPAUSE_REGISTRY: 30,
  CONSENT_GRANT: 10,
  CONTENT_ACCESS: 20,
  CONTENT_UPLOAD: 15,
  ASSET_VIEW: 5,
};

const CLASSIFICATION_WEIGHT: Record<string, number> = {
  PUBLIC: 0,
  CONTROLLED: 5,
  SENSITIVE: 15,
  HIGHLY_SENSITIVE: 30,
  CRITICAL: 45,
};

const RISK_WEIGHT: Record<RiskLevel, number> = {
  LOW: 0,
  MEDIUM: 10,
  HIGH: 25,
  CRITICAL: 40,
};

/** Level thresholds over the additive score. */
const ELEVATED_THRESHOLD = 40;
const QUANTUM_THRESHOLD = 70;

export interface AssurancePolicyInput {
  operation: AssuranceOperation;
  /** Session/DB-derived role name. Never a client assertion. */
  role: string;
  assetClassification?: string | null;
  riskLevel?: RiskLevel | null;
  /** Advisory intelligence score 0-100, refined into the risk step. */
  riskScore?: number | null;
  custodyRelation?: CustodyRelation | null;
  approvalStatus?: ApprovalState | null;
  /** True only for a SERVER-verified step-up for this exact purpose. */
  stepUpSatisfied?: boolean;
}

export interface AssurancePolicyResult {
  level: AssuranceLevel;
  algorithms: readonly SignatureAlgorithm[];
  requiresDualSignature: boolean;
  requiresStepUp: boolean;
  score: number;
  reasonCodes: AssuranceReasonCode[];
  explanation: string;
}

function classificationWeight(classification: string | null | undefined, reasons: AssuranceReasonCode[]): number {
  if (classification == null || classification === "") return 0;
  const known = Object.prototype.hasOwnProperty.call(CLASSIFICATION_WEIGHT, classification);
  if (!known) {
    // Fail closed: an unrecognised classification is treated as the worst case.
    reasons.push("CLASSIFICATION_UNKNOWN");
    return CLASSIFICATION_WEIGHT.CRITICAL;
  }
  if (classification === "HIGHLY_SENSITIVE") reasons.push("CLASSIFICATION_HIGHLY_SENSITIVE");
  if (classification === "CRITICAL") reasons.push("CLASSIFICATION_CRITICAL");
  return CLASSIFICATION_WEIGHT[classification];
}

function riskWeight(input: AssurancePolicyInput, reasons: AssuranceReasonCode[]): number {
  const level = input.riskLevel ?? "LOW";
  if (level === "MEDIUM") reasons.push("RISK_MEDIUM");
  if (level === "HIGH") reasons.push("RISK_HIGH");
  if (level === "CRITICAL") reasons.push("RISK_CRITICAL");
  const base = RISK_WEIGHT[level] ?? RISK_WEIGHT.CRITICAL;
  // A high advisory score nudges the step up by at most one band worth of points.
  // The advisory score can only ever ADD, never subtract — a bug or a
  // manipulated score cannot lower the required assurance.
  const score = typeof input.riskScore === "number" && Number.isFinite(input.riskScore)
    ? Math.max(0, Math.min(100, input.riskScore))
    : 0;
  return base + (score >= 75 ? 10 : score >= 50 ? 5 : 0);
}

/**
 * The single entry point. Pure function: identical input → identical output.
 */
export function evaluateAssurance(input: AssurancePolicyInput): AssurancePolicyResult {
  const reasons: AssuranceReasonCode[] = [];
  let score = 0;

  // ---- operation ------------------------------------------------------
  const opWeight = OPERATION_WEIGHT[input.operation] ?? OPERATION_WEIGHT.ASSET_FORCE_TRANSFER ?? 60;
  score += opWeight;
  if ((OPERATION_WEIGHT[input.operation] ?? 60) <= 20) reasons.push("OP_BASELINE");
  else reasons.push("OP_ELEVATED_RISK");
  if (ADMINISTRATIVE_OPERATIONS.has(input.operation)) reasons.push("OP_ADMINISTRATIVE");
  const irreversible = IRREVERSIBLE_OPERATIONS.has(input.operation);
  if (irreversible) reasons.push("OP_IRREVERSIBLE");

  // ---- asset classification -------------------------------------------
  score += classificationWeight(input.assetClassification, reasons);

  // ---- advisory risk ---------------------------------------------------
  score += riskWeight(input, reasons);

  // ---- actor role ------------------------------------------------------
  const role = (input.role ?? "").toUpperCase();
  if (role === "ADMIN") {
    // Administrative authority has global blast radius: an admin action that
    // goes wrong affects every tenant, so it is held to a higher bar.
    score += 10;
    reasons.push("ROLE_ADMIN_BLAST_RADIUS");
  }
  if (role === "AUDITOR") {
    // Auditors are read-only by role contract. Any mutating operation labelled
    // as an auditor action is anomalous and is treated as elevated.
    score += 15;
    reasons.push("ROLE_AUDITOR_READ_ONLY");
  }

  // ---- custody ---------------------------------------------------------
  const custody = input.custodyRelation ?? "NOT_APPLICABLE";
  if (custody === "NONE") {
    score += 15;
    reasons.push("CUSTODY_MISMATCH");
  }
  if (custody === "OWNER") {
    score += 5;
    reasons.push("CUSTODY_NOT_CUSTODIAN");
  }

  // ---- approval state --------------------------------------------------
  const approval = input.approvalStatus ?? "NOT_REQUIRED";
  if (approval === "PENDING") {
    score += 10;
    reasons.push("APPROVAL_MISSING");
  }
  if (approval === "REJECTED") {
    score += 20;
    reasons.push("APPROVAL_REJECTED");
  }

  // ---- step-up ---------------------------------------------------------
  // A missing server-verified step-up is evidence about the SESSION, not an
  // authorization decision; it raises the bar rather than denying.
  if (input.stepUpSatisfied !== true && (opWeight >= 25 || irreversible)) {
    score += 15;
    reasons.push("STEP_UP_NOT_SATISFIED");
  }

  // ---- platform floors (non-negotiable minimums) -----------------------
  // Any irreversible or role-administration operation is at least ELEVATED.
  const elevatedFloor = irreversible || ADMINISTRATIVE_OPERATIONS.has(input.operation);
  // A post-quantum signature is mandated when the combination is severe
  // enough that a future quantum adversary could retroactively forge it, or
  // when the operation is on the non-negotiable PQC list.
  let quantumMandated = score >= QUANTUM_THRESHOLD || QUANTUM_MANDATED_OPERATIONS.has(input.operation);
  if (input.riskLevel === "CRITICAL") quantumMandated = true;
  if (irreversible && (input.assetClassification === "CRITICAL" || role === "ADMIN")) {
    quantumMandated = true;
  }
  if (quantumMandated) reasons.push("PQC_POLICY_MANDATED");
  if (elevatedFloor) reasons.push("PLATFORM_FLOOR");

  const level: AssuranceLevel = quantumMandated
    ? "QUANTUM_HARDENED"
    : score >= ELEVATED_THRESHOLD || elevatedFloor
      ? "ELEVATED"
      : "BASELINE";

  const algorithms = ALGORITHM_BY_LEVEL[level];
  const explanation =
    level === "QUANTUM_HARDENED"
      ? `Score ${score} with mandatory post-quantum floor: ECDSA (secp256k1) AND ML-DSA-65 signatures are required over one canonical payload.`
      : level === "ELEVATED"
        ? `Score ${score}: a server-verified step-up for this exact operation is required on top of the session-bound ECDSA signature.`
        : `Score ${score}: the session-bound ECDSA signature is sufficient.`;

  return {
    level,
    algorithms,
    requiresDualSignature: algorithms.includes("ML_DSA_65"),
    requiresStepUp: level !== "BASELINE",
    score,
    reasonCodes: reasons,
    explanation,
  };
}

/**
 * Governance proposal kinds → assurance operations. Kept here (not in the
 * router) so the mapping is testable in isolation and cannot drift.
 */
export const GOVERNANCE_KIND_TO_OPERATION: Record<string, AssuranceOperation> = {
  BURN_NFT: "ASSET_BURN",
  FORCE_TRANSFER: "ASSET_FORCE_TRANSFER",
  PAUSE_REGISTRY: "PAUSE_REGISTRY",
  UNPAUSE_REGISTRY: "UNPAUSE_REGISTRY",
  GRANT_ROLE: "IDENTITY_ROLE_ADMIN",
  REVOKE_ROLE: "IDENTITY_ROLE_ADMIN",
  DEACTIVATE_IDENTITY: "IDENTITY_STATUS_CHANGE",
};

/**
 * Governance proposal kinds whose assurance requirement is evaluated against
 * the target asset's classification when one is supplied. Kinds that have no
 * asset target simply pass `assetClassification: null`.
 */
export const GOVERNANCE_KINDS_WITH_ASSET_TARGET: ReadonlySet<string> = new Set([
  "BURN_NFT",
  "FORCE_TRANSFER",
]);
