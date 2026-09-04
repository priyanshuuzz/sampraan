import { describe, expect, it } from "vitest";
import {
  authorizationService,
  type AuthorizationRequest,
} from "./authorization.service";

/**
 * Engine-level tests (union of two branches).
 *
 * The engine is the SOLE decision authority: identity status is checked
 * before permissions, USER + HIGHLY_SENSITIVE is denied by policy, and
 * HIGHLY_SENSITIVE without server-verified step-up yields CHALLENGE.
 * Both suites below run against the same unchanged engine; the union keeps
 * every regression case from either branch.
 */

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

    it("ALLOWs an active identity holding asset:transfer on a controlled asset", () => {
      const result = authorizationService.evaluate(
        transferRequest({ assetClassification: "CONTROLLED" })
      );
      expect(result.decision).toBe("ALLOW");
      expect(result.decisionId).toMatch(/[0-9a-f-]{36}/);
      expect(result.timestamp).toBeTruthy();
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

    it("allows a highly sensitive transfer for ADMIN after step-up authentication", () => {
      // The engine still exposes the step-up hook for a future
      // server-verified mechanism; the tRPC boundary never forwards client
      // assertions into it (see routers.security.test.ts).
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
  });

  describe("DENY — identity status first", () => {
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

    it("DENIES a suspended identity even when it holds the permission", () => {
      const result = authorizationService.evaluate(
        transferRequest({
          identityStatus: "SUSPENDED",
          assetClassification: "CONTROLLED",
        })
      );
      expect(result.decision).toBe("DENY");
      expect(result.reason).toContain("suspended");
    });

    it("DENIES a suspended ADMIN on a HIGHLY_SENSITIVE asset even with step-up (status checked first)", () => {
      const result = authorizationService.evaluate(
        transferRequest({
          identityStatus: "SUSPENDED",
          role: "ADMIN",
          assetClassification: "HIGHLY_SENSITIVE",
          context: { stepUpAuthenticated: true },
        })
      );
      expect(result.decision).toBe("DENY");
      expect(result.reason).toContain("suspended");
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

    it("DENIES an unregistered actor (no SAMPRAAN identity)", () => {
      const result = authorizationService.evaluate(
        transferRequest({
          identityStatus: "UNREGISTERED",
          assetClassification: "CONTROLLED",
        })
      );
      expect(result.decision).toBe("DENY");
      expect(result.reason).toContain("unregistered");
    });
  });

  describe("DENY — permissions", () => {
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

    it("DENIES an identity with no permissions", () => {
      const result = authorizationService.evaluate(
        transferRequest({ permissions: [], assetClassification: "CONTROLLED" })
      );
      expect(result.decision).toBe("DENY");
    });
  });

  describe("DENY — HIGHLY_SENSITIVE policy (POLICY-HIGH-SENS-TRANSFER)", () => {
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

  describe("CHALLENGE — step-up (POLICY-STEP-UP)", () => {
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
      expect(result.policyId).toBe("POLICY-STEP-UP");
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

    it("keeps the decisionId well-formed across the DENY branch metadata", () => {
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
