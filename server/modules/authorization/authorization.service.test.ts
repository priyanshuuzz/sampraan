import { describe, expect, it } from "vitest";
import {
  authorizationService,
  type AuthorizationRequest,
} from "./authorization.service";

const baseRequest: AuthorizationRequest = {
  identityStatus: "ACTIVE",
  role: "USER",
  permissions: ["asset:transfer"],
  resourceType: "asset",
  action: "TRANSFER",
  assetClassification: "CONTROLLED",
};

describe("AuthorizationService.evaluate", () => {
  it("ALLOWs an active identity holding the required permission on a controlled asset", () => {
    const result = authorizationService.evaluate(baseRequest);
    expect(result.decision).toBe("ALLOW");
    expect(result.decisionId).toMatch(/[0-9a-f-]{36}/);
    expect(result.timestamp).toBeTruthy();
  });

  it("DENIES a suspended identity even when it holds the permission", () => {
    const result = authorizationService.evaluate({
      ...baseRequest,
      identityStatus: "SUSPENDED",
    });
    expect(result.decision).toBe("DENY");
    expect(result.reason).toContain("suspended");
  });

  it("DENIES a revoked identity even when it holds the permission", () => {
    const result = authorizationService.evaluate({
      ...baseRequest,
      identityStatus: "REVOKED",
    });
    expect(result.decision).toBe("DENY");
    expect(result.reason).toContain("revoked");
  });

  it("DENIES an unregistered actor (no SAMPRAAN identity)", () => {
    const result = authorizationService.evaluate({
      ...baseRequest,
      identityStatus: "UNREGISTERED",
    });
    expect(result.decision).toBe("DENY");
    expect(result.reason).toContain("unregistered");
  });

  it("DENIES an active identity that lacks the required permission", () => {
    const result = authorizationService.evaluate({
      ...baseRequest,
      permissions: ["asset:read"],
    });
    expect(result.decision).toBe("DENY");
    expect(result.reason).toContain("asset:transfer");
  });

  it("DENIES an identity with no permissions", () => {
    const result = authorizationService.evaluate({
      ...baseRequest,
      permissions: [],
    });
    expect(result.decision).toBe("DENY");
  });

  it("allows administration:manage to satisfy the permission check without the specific permission", () => {
    const result = authorizationService.evaluate({
      ...baseRequest,
      permissions: ["administration:manage"],
    });
    expect(result.decision).toBe("ALLOW");
  });

  it("DENIES a USER transferring a HIGHLY_SENSITIVE asset (policy guard)", () => {
    const result = authorizationService.evaluate({
      ...baseRequest,
      assetClassification: "HIGHLY_SENSITIVE",
    });
    expect(result.decision).toBe("DENY");
    expect(result.reason).toContain("HIGHLY_SENSITIVE");
    expect(result.policyId).toBe("POLICY-HIGH-SENS-TRANSFER");
  });

  it("CHALLENGEs an ADMIN transferring a HIGHLY_SENSITIVE asset without step-up authentication", () => {
    const result = authorizationService.evaluate({
      ...baseRequest,
      role: "ADMIN",
      permissions: ["administration:manage"],
      assetClassification: "HIGHLY_SENSITIVE",
      context: { stepUpAuthenticated: false },
    });
    expect(result.decision).toBe("CHALLENGE");
    expect(result.reason).toContain("Step-up");
    expect(result.policyId).toBe("POLICY-STEP-UP");
  });

  it("CHALLENGEs when no step-up context is provided at all", () => {
    const result = authorizationService.evaluate({
      ...baseRequest,
      role: "ADMIN",
      permissions: ["administration:manage"],
      assetClassification: "HIGHLY_SENSITIVE",
    });
    expect(result.decision).toBe("CHALLENGE");
  });

  it("ALLOWs an ADMIN transferring a HIGHLY_SENSITIVE asset with step-up authentication", () => {
    const result = authorizationService.evaluate({
      ...baseRequest,
      role: "ADMIN",
      permissions: ["administration:manage"],
      assetClassification: "HIGHLY_SENSITIVE",
      context: { stepUpAuthenticated: true },
    });
    expect(result.decision).toBe("ALLOW");
  });

  it("DENIES a suspended ADMIN on a HIGHLY_SENSITIVE asset even with step-up (status checked first)", () => {
    const result = authorizationService.evaluate({
      ...baseRequest,
      identityStatus: "SUSPENDED",
      role: "ADMIN",
      permissions: ["administration:manage"],
      assetClassification: "HIGHLY_SENSITIVE",
      context: { stepUpAuthenticated: true },
    });
    expect(result.decision).toBe("DENY");
    expect(result.reason).toContain("suspended");
  });

  it("produces a unique decisionId per evaluation", () => {
    const a = authorizationService.evaluate(baseRequest);
    const b = authorizationService.evaluate(baseRequest);
    expect(a.decisionId).not.toBe(b.decisionId);
  });
});
