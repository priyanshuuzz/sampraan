import { describe, expect, it } from "vitest";
import {
  authorizationService,
  type AuthorizationRequest,
} from "./authorization.service";

const baseRequest: AuthorizationRequest = {
  identityStatus: "ACTIVE",
  role: "USER",
  permissions: ["asset:read"],
  resourceType: "asset",
  action: "READ",
};

const transferRequest = (
  overrides: Partial<AuthorizationRequest> = {}
): AuthorizationRequest => ({
  ...baseRequest,
  action: "TRANSFER",
  permissions: ["asset:transfer"],
  ...overrides,
});

describe("AuthorizationService.evaluate", () => {
  describe("ALLOW", () => {
    it("allows an ACTIVE identity that holds the exact permission", () => {
      const result = authorizationService.evaluate(baseRequest);
      expect(result.decision).toBe("ALLOW");
      expect(result.policyId).toBeUndefined();
    });

    it("allows an ADMIN regardless of the permissions list", () => {
      const result = authorizationService.evaluate({
        ...baseRequest,
        role: "ADMIN",
        permissions: [],
        action: "TRANSFER",
        assetClassification: "CONTROLLED",
      });
      expect(result.decision).toBe("ALLOW");
    });

    it("allows any action for a holder of administration:manage", () => {
      const result = authorizationService.evaluate({
        ...baseRequest,
        role: "OPERATOR",
        permissions: ["administration:manage"],
        resourceType: "policy",
        action: "DELETE",
      });
      expect(result.decision).toBe("ALLOW");
    });

    it("allows a USER transfer of a non-sensitive asset with asset:transfer", () => {
      const result = authorizationService.evaluate(
        transferRequest({ assetClassification: "CONTROLLED" })
      );
      expect(result.decision).toBe("ALLOW");
    });

    it("allows a highly sensitive transfer for ADMIN after step-up authentication", () => {
      const result = authorizationService.evaluate(
        transferRequest({
          role: "ADMIN",
          assetClassification: "HIGHLY_SENSITIVE",
          context: { stepUpAuthenticated: true },
        })
      );
      expect(result.decision).toBe("ALLOW");
      expect(result.policyId).toBeUndefined();
    });

    it("normalizes resource type and action case when matching permissions", () => {
      const result = authorizationService.evaluate({
        ...baseRequest,
        resourceType: "Asset",
        action: "TRANSFER",
        permissions: ["asset:transfer"],
        assetClassification: "CONTROLLED",
      });
      expect(result.decision).toBe("ALLOW");
    });
  });

  describe("DENY", () => {
    it("denies a SUSPENDED identity before any permission check", () => {
      const result = authorizationService.evaluate({
        ...baseRequest,
        identityStatus: "SUSPENDED",
        role: "ADMIN",
        permissions: [],
      });
      expect(result.decision).toBe("DENY");
      expect(result.reason).toBe("Identity is suspended");
      expect(result.policyId).toBeUndefined();
    });

    it("denies a REVOKED identity", () => {
      const result = authorizationService.evaluate({
        ...baseRequest,
        identityStatus: "REVOKED",
      });
      expect(result.decision).toBe("DENY");
      expect(result.reason).toBe("Identity is revoked");
    });

    it("denies any non-ACTIVE identity status", () => {
      const result = authorizationService.evaluate({
        ...baseRequest,
        identityStatus: "PENDING",
      });
      expect(result.decision).toBe("DENY");
      expect(result.reason).toBe("Identity is pending");
    });

    it("denies when the role does not hold the required permission", () => {
      const result = authorizationService.evaluate({
        ...baseRequest,
        action: "TRANSFER",
        permissions: ["asset:read"],
        assetClassification: "CONTROLLED",
      });
      expect(result.decision).toBe("DENY");
      expect(result.reason).toBe("Role USER does not hold asset:transfer");
      expect(result.policyId).toBeUndefined();
    });

    it("denies a USER transferring a HIGHLY_SENSITIVE asset even with step-up", () => {
      const result = authorizationService.evaluate(
        transferRequest({
          assetClassification: "HIGHLY_SENSITIVE",
          context: { stepUpAuthenticated: true },
        })
      );
      expect(result.decision).toBe("DENY");
      expect(result.reason).toBe(
        "Role USER cannot TRANSFER HIGHLY_SENSITIVE asset"
      );
      expect(result.policyId).toBe("POLICY-HIGH-SENS-TRANSFER");
    });

    it("denies a USER transferring a HIGHLY_SENSITIVE asset even with administration:manage", () => {
      const result = authorizationService.evaluate(
        transferRequest({
          assetClassification: "HIGHLY_SENSITIVE",
          permissions: ["administration:manage"],
        })
      );
      expect(result.decision).toBe("DENY");
      expect(result.policyId).toBe("POLICY-HIGH-SENS-TRANSFER");
    });
  });

  describe("CHALLENGE", () => {
    it("challenges an ADMIN highly sensitive transfer without step-up", () => {
      const result = authorizationService.evaluate(
        transferRequest({
          role: "ADMIN",
          assetClassification: "HIGHLY_SENSITIVE",
        })
      );
      expect(result.decision).toBe("CHALLENGE");
      expect(result.reason).toBe(
        "Step-up authentication is required for highly sensitive transfers"
      );
      expect(result.policyId).toBe("POLICY-STEP-UP");
    });

    it("challenges when stepUpAuthenticated is explicitly false", () => {
      const result = authorizationService.evaluate(
        transferRequest({
          role: "ADMIN",
          assetClassification: "HIGHLY_SENSITIVE",
          context: { stepUpAuthenticated: false },
        })
      );
      expect(result.decision).toBe("CHALLENGE");
    });

    it("challenges a permitted non-ADMIN role on highly sensitive transfers", () => {
      const result = authorizationService.evaluate(
        transferRequest({
          role: "MANAGER",
          assetClassification: "HIGHLY_SENSITIVE",
        })
      );
      expect(result.decision).toBe("CHALLENGE");
      expect(result.policyId).toBe("POLICY-STEP-UP");
    });

    it("allows the same MANAGER role after step-up", () => {
      const result = authorizationService.evaluate(
        transferRequest({
          role: "MANAGER",
          assetClassification: "HIGHLY_SENSITIVE",
          context: { stepUpAuthenticated: true },
        })
      );
      expect(result.decision).toBe("ALLOW");
    });
  });

  describe("result metadata", () => {
    it("returns a fresh UUID decisionId and an ISO timestamp per evaluation", () => {
      const first = authorizationService.evaluate(baseRequest);
      const second = authorizationService.evaluate(baseRequest);

      expect(first.decisionId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      );
      expect(first.decisionId).not.toBe(second.decisionId);
      expect(Number.isNaN(Date.parse(first.timestamp))).toBe(false);
      expect(Number.isNaN(Date.parse(second.timestamp))).toBe(false);
    });

    it("keeps the decisionId stable across the DENY branch metadata", () => {
      const result = authorizationService.evaluate({
        ...baseRequest,
        identityStatus: "REVOKED",
      });
      expect(result.decisionId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      );
    });
  });
});
