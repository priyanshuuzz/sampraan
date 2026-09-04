import { randomUUID } from "node:crypto";

/**
 * SAMPRAAN authorization engine.
 *
 * Deterministic policy evaluation producing ALLOW / DENY / CHALLENGE.
 * This is the backend security boundary: frontend permission checks are UX only.
 */

export type AuthorizationDecision = "ALLOW" | "DENY" | "CHALLENGE";

export interface AuthorizationRequest {
  identityStatus: string;
  role: string;
  permissions: string[];
  resourceType: string;
  action: string;
  assetClassification?: string;
  context?: { stepUpAuthenticated?: boolean };
}

export interface AuthorizationResult {
  decision: AuthorizationDecision;
  decisionId: string;
  reason: string;
  policyId?: string;
  timestamp: string;
}

export class AuthorizationService {
  evaluate(request: AuthorizationRequest): AuthorizationResult {
    const timestamp = new Date().toISOString();
    const decisionId = randomUUID();

    if (request.identityStatus !== "ACTIVE") {
      return {
        decision: "DENY",
        decisionId,
        reason: `Identity is ${request.identityStatus.toLowerCase()}`,
        timestamp,
      };
    }

    const permission = `${request.resourceType.toLowerCase()}:${request.action.toLowerCase()}`;
    if (
      request.role !== "ADMIN" &&
      !request.permissions.includes(permission) &&
      !request.permissions.includes("administration:manage")
    ) {
      return {
        decision: "DENY",
        decisionId,
        reason: `Role ${request.role} does not hold ${permission}`,
        timestamp,
      };
    }

    if (
      request.action === "TRANSFER" &&
      request.assetClassification === "HIGHLY_SENSITIVE" &&
      request.role === "USER"
    ) {
      return {
        decision: "DENY",
        decisionId,
        reason: "Role USER cannot TRANSFER HIGHLY_SENSITIVE asset",
        policyId: "POLICY-HIGH-SENS-TRANSFER",
        timestamp,
      };
    }

    if (
      request.action === "TRANSFER" &&
      request.assetClassification === "HIGHLY_SENSITIVE" &&
      request.context?.stepUpAuthenticated !== true
    ) {
      return {
        decision: "CHALLENGE",
        decisionId,
        reason: "Step-up authentication is required for highly sensitive transfers",
        policyId: "POLICY-STEP-UP",
        timestamp,
      };
    }

    return {
      decision: "ALLOW",
      decisionId,
      reason:
        "Identity, role, permission, resource, and policy checks passed",
      timestamp,
    };
  }
}

export const authorizationService = new AuthorizationService();
