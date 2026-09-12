/**
 * LOOP 4+5+6 — authorization engine ABAC branch tests (custody, approval,
 * advisory risk elevation). These extend — never replace — the original 22
 * engine tests, which continue to pass unchanged.
 */
import { describe, expect, it } from "vitest";
import { authorizationService } from "./authorization.service";

const base = {
  identityStatus: "ACTIVE",
  role: "MANAGER",
  permissions: ["asset:transfer"],
  resourceType: "asset",
  action: "TRANSFER",
  assetClassification: "CONTROLLED",
  actorIdentityId: "actor-1",
  currentCustodianIdentityId: "actor-1",
};

describe("ABAC custody control (POLICY-CUSTODY)", () => {
  it("ALLOWs the current custodian transferring a CONTROLLED asset", () => {
    const result = authorizationService.evaluate(base);
    expect(result.decision).toBe("ALLOW");
  });

  it("DENIES a non-custodian MANAGER transferring an asset they do not hold", () => {
    const result = authorizationService.evaluate({
      ...base,
      currentCustodianIdentityId: "someone-else",
    });
    expect(result.decision).toBe("DENY");
    expect(result.policyId).toBe("POLICY-CUSTODY");
  });

  it("ADMIN may transfer regardless of custody (asset administration)", () => {
    const result = authorizationService.evaluate({
      ...base,
      role: "ADMIN",
      permissions: [],
      currentCustodianIdentityId: "someone-else",
    });
    expect(result.decision).toBe("ALLOW");
  });

  it("AUDITOR with a stolen permission string still cannot transfer a non-custodied asset", () => {
    const result = authorizationService.evaluate({
      ...base,
      role: "AUDITOR",
      permissions: ["asset:transfer"],
      currentCustodianIdentityId: "someone-else",
    });
    expect(result.decision).toBe("DENY");
  });

  it("skips the custody branch when custody is unknown (legacy callers)", () => {
    const { currentCustodianIdentityId: _omit, ...noCustody } = base;
    const result = authorizationService.evaluate(noCustody);
    expect(result.decision).toBe("ALLOW");
  });
});

describe("ABAC approval state (POLICY-APPROVAL / POLICY-APPROVAL-REJECTED)", () => {
  it("CHALLENGEs an approval-gated operation without an APPROVED approval", () => {
    const result = authorizationService.evaluate({
      ...base,
      context: { approvalRequired: true },
      approvalStatus: "PENDING",
    });
    expect(result.decision).toBe("CHALLENGE");
    expect(result.policyId).toBe("POLICY-APPROVAL");
  });

  it("ALLOWs once the approval is APPROVED", () => {
    const result = authorizationService.evaluate({
      ...base,
      context: { approvalRequired: true },
      approvalStatus: "APPROVED",
    });
    expect(result.decision).toBe("ALLOW");
  });

  it("DENIES a REJECTED approval even with step-up and custody", () => {
    const result = authorizationService.evaluate({
      ...base,
      context: { approvalRequired: true, stepUpAuthenticated: true },
      approvalStatus: "REJECTED",
    });
    expect(result.decision).toBe("DENY");
    expect(result.policyId).toBe("POLICY-APPROVAL-REJECTED");
  });

  it("never reaches the approval branch for non-transfer actions", () => {
    const result = authorizationService.evaluate({
      ...base,
      action: "READ",
      permissions: ["asset:read"],
      context: { approvalRequired: true },
      approvalStatus: "PENDING",
    });
    expect(result.decision).toBe("ALLOW");
  });
});

describe("Advisory risk elevation (POLICY-RISK-ELEVATION)", () => {
  it("elevates a HIGH-risk ALLOW path to CHALLENGE", () => {
    const result = authorizationService.evaluate({ ...base, riskLevel: "HIGH" });
    expect(result.decision).toBe("CHALLENGE");
    expect(result.policyId).toBe("POLICY-RISK-ELEVATION");
  });

  it("risk can NEVER grant: HIGH risk does not override a permission DENY", () => {
    const result = authorizationService.evaluate({
      ...base,
      permissions: ["asset:read"],
      riskLevel: "LOW",
    });
    expect(result.decision).toBe("DENY");
  });

  it("risk can NEVER grant: HIGH risk does not override a revoked identity", () => {
    const result = authorizationService.evaluate({
      ...base,
      identityStatus: "REVOKED",
      riskLevel: "HIGH",
    });
    expect(result.decision).toBe("DENY");
  });

  it("MEDIUM risk does not elevate", () => {
    const result = authorizationService.evaluate({ ...base, riskLevel: "MEDIUM" });
    expect(result.decision).toBe("ALLOW");
  });
});

describe("Sensitivity gate composition", () => {
  it("HIGHLY_SENSITIVE + custody + step-up + approval → ALLOW (full demo path)", () => {
    const result = authorizationService.evaluate({
      ...base,
      assetClassification: "HIGHLY_SENSITIVE",
      context: { stepUpAuthenticated: true, approvalRequired: true },
      approvalStatus: "APPROVED",
    });
    expect(result.decision).toBe("ALLOW");
  });

  it("HIGHLY_SENSITIVE without step-up → CHALLENGE before approval is considered", () => {
    const result = authorizationService.evaluate({
      ...base,
      assetClassification: "HIGHLY_SENSITIVE",
      context: { stepUpAuthenticated: false, approvalRequired: true },
      approvalStatus: "APPROVED",
    });
    expect(result.decision).toBe("CHALLENGE");
    expect(result.policyId).toBe("POLICY-STEP-UP");
  });
});
