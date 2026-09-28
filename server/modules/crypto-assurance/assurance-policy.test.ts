/**
 * Crypto assurance POLICY — unit tests.
 *
 * These tests are the contract for the policy engine:
 *  - DETERMINISM: identical input → identical level, score and reason codes;
 *  - NO USER SELECTION: the level deterministically fixes the algorithm set, and
 *    there is no input that lets a caller request or downgrade an algorithm;
 *  - MONOTONICITY: adding risk (worse classification, higher risk, custody
 *    mismatch, missing step-up) can never LOWER the required level;
 *  - FAIL CLOSED on an unknown classification;
 *  - FLOORS: irreversible / role-administration operations are never BASELINE,
 *    and the non-negotiable set always mandates ML-DSA-65.
 */
import { describe, expect, it } from "vitest";
import {
  ALGORITHM_BY_LEVEL,
  GOVERNANCE_KIND_TO_OPERATION,
  evaluateAssurance,
  type AssuranceOperation,
  type AssurancePolicyInput,
} from "./assurance-policy";

const base: AssurancePolicyInput = {
  operation: "ASSET_VIEW",
  role: "USER",
  assetClassification: null,
  riskLevel: "LOW",
  riskScore: null,
  custodyRelation: "NOT_APPLICABLE",
  approvalStatus: "NOT_REQUIRED",
  stepUpSatisfied: false,
};

const withInput = (patch: Partial<AssurancePolicyInput>) => evaluateAssurance({ ...base, ...patch });

describe("assurance policy — deterministic + explainable", () => {
  it("returns identical results for identical inputs (no clock, no randomness)", () => {
    const a = withInput({ operation: "ASSET_TRANSFER", assetClassification: "HIGHLY_SENSITIVE", role: "MANAGER" });
    const b = withInput({ operation: "ASSET_TRANSFER", assetClassification: "HIGHLY_SENSITIVE", role: "MANAGER" });
    expect(b).toEqual(a);
  });

  it("always returns a non-empty explanation and at least one reason code", () => {
    for (const operation of Object.keys(GOVERNANCE_KIND_TO_OPERATION) as string[]) {
      const result = withInput({ operation: GOVERNANCE_KIND_TO_OPERATION[operation] as AssuranceOperation });
      expect(result.explanation.length).toBeGreaterThan(20);
      expect(result.reasonCodes.length).toBeGreaterThan(0);
    }
  });

  it("pins the algorithm set to the level — no input can select an algorithm", () => {
    const baseline = withInput({ operation: "ASSET_VIEW" });
    expect(baseline.level).toBe("BASELINE");
    expect(baseline.algorithms).toEqual(ALGORITHM_BY_LEVEL.BASELINE);
    expect(baseline.requiresDualSignature).toBe(false);

    const quantum = withInput({ operation: "ASSET_BURN" });
    expect(quantum.level).toBe("QUANTUM_HARDENED");
    expect(quantum.algorithms).toEqual(["ECDSA_SECP256K1", "ML_DSA_65"]);
    expect(quantum.requiresDualSignature).toBe(true);
  });
});

describe("assurance policy — floors and mandates", () => {
  it("never allows an irreversible operation at BASELINE", () => {
    for (const operation of ["ASSET_BURN", "ASSET_FORCE_TRANSFER", "IDENTITY_STATUS_CHANGE", "KEY_RECOVERY_EXECUTE", "DID_KEY_REVOKE"] as AssuranceOperation[]) {
      const result = withInput({ operation, role: "USER" });
      expect(result.level).not.toBe("BASELINE");
    }
  });

  it("mandates ML-DSA-65 for the non-negotiable operation set", () => {
    for (const operation of ["ASSET_BURN", "ASSET_FORCE_TRANSFER", "IDENTITY_ROLE_ADMIN", "GOVERNANCE_CONFIG", "IDENTITY_STATUS_CHANGE", "KEY_RECOVERY_EXECUTE"] as AssuranceOperation[]) {
      const result = withInput({ operation });
      expect(result.level).toBe("QUANTUM_HARDENED");
      expect(result.reasonCodes).toContain("PQC_POLICY_MANDATED");
    }
  });

  it("keeps immediately-reversible pause/unpause at ELEVATED (step-up, no PQC)", () => {
    const pause = withInput({ operation: "PAUSE_REGISTRY", role: "ADMIN" });
    expect(pause.level).toBe("ELEVATED");
    expect(pause.requiresDualSignature).toBe(false);
    expect(pause.requiresStepUp).toBe(true);
  });

  it("escalates a CRITICAL asset classification to QUANTUM_HARDENED on transfer", () => {
    const result = withInput({ operation: "ASSET_TRANSFER", assetClassification: "CRITICAL", role: "MANAGER" });
    expect(result.level).toBe("QUANTUM_HARDENED");
    expect(result.reasonCodes).toContain("CLASSIFICATION_CRITICAL");
  });
});

describe("assurance policy — monotonicity (risk can only raise the bar)", () => {
  const levelRank = { BASELINE: 0, ELEVATED: 1, QUANTUM_HARDENED: 2 } as const;

  it("an unknown classification is treated as CRITICAL (fail closed)", () => {
    const unknown = withInput({ operation: "ASSET_TRANSFER", assetClassification: "TOTALLY_UNKNOWN" });
    const critical = withInput({ operation: "ASSET_TRANSFER", assetClassification: "CRITICAL" });
    expect(unknown.reasonCodes).toContain("CLASSIFICATION_UNKNOWN");
    expect(unknown.score).toBe(critical.score);
    expect(levelRank[unknown.level]).toBe(levelRank[critical.level]);
  });

  it("higher classification / risk / custody mismatch never lowers the level", () => {
    const baseline = withInput({ operation: "ASSET_TRANSFER", role: "MANAGER" });
    const worse = [
      withInput({ operation: "ASSET_TRANSFER", role: "MANAGER", assetClassification: "SENSITIVE" }),
      withInput({ operation: "ASSET_TRANSFER", role: "MANAGER", assetClassification: "HIGHLY_SENSITIVE" }),
      withInput({ operation: "ASSET_TRANSFER", role: "MANAGER", riskLevel: "HIGH" }),
      withInput({ operation: "ASSET_TRANSFER", role: "MANAGER", riskLevel: "CRITICAL" }),
      withInput({ operation: "ASSET_TRANSFER", role: "MANAGER", custodyRelation: "NONE" }),
      withInput({ operation: "ASSET_TRANSFER", role: "MANAGER", approvalStatus: "REJECTED" }),
    ];
    for (const variant of worse) {
      expect(variant.score).toBeGreaterThanOrEqual(baseline.score);
      expect(levelRank[variant.level]).toBeGreaterThanOrEqual(levelRank[baseline.level]);
    }
  });

  it("a satisfied step-up lowers the score but never the mandated floor", () => {
    const unsatisfied = withInput({ operation: "ASSET_FORCE_TRANSFER" });
    const satisfied = withInput({ operation: "ASSET_FORCE_TRANSFER", stepUpSatisfied: true });
    expect(satisfied.score).toBeLessThan(unsatisfied.score);
    expect(satisfied.level).toBe("QUANTUM_HARDENED");
  });

  it("an ADMIN actor is held to at least the same bar as a USER actor", () => {
    const user = withInput({ operation: "ASSET_TRANSFER", role: "USER" });
    const admin = withInput({ operation: "ASSET_TRANSFER", role: "ADMIN" });
    expect(admin.score).toBeGreaterThanOrEqual(user.score);
  });
});

describe("assurance policy — governance kind mapping", () => {
  it("maps every governance kind to an operation and scores it", () => {
    for (const [kind, operation] of Object.entries(GOVERNANCE_KIND_TO_OPERATION)) {
      const result = withInput({ operation, role: "ADMIN" });
      expect(result.level).toMatch(/^(BASELINE|ELEVATED|QUANTUM_HARDENED)$/);
      expect(kind.length).toBeGreaterThan(0);
    }
  });

  it("every emitted reason code is in the documented vocabulary", async () => {
    const { ASSURANCE_REASON_CODES } = await import("./assurance-policy");
    const operations = Object.keys(GOVERNANCE_KIND_TO_OPERATION).map(k => GOVERNANCE_KIND_TO_OPERATION[k]);
    for (const operation of operations) {
      for (const code of withInput({ operation, role: "ADMIN", assetClassification: "CRITICAL", riskLevel: "HIGH" }).reasonCodes) {
        expect(ASSURANCE_REASON_CODES).toContain(code);
      }
    }
  });
});
