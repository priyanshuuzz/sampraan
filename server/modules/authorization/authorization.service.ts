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
  /** ABAC (LOOP 4): the actor's SAMPRAAN identity id, resolved server-side. */
  actorIdentityId?: string;
  /** ABAC: the asset's CURRENT custodian identity id, resolved server-side. */
  currentCustodianIdentityId?: string;
  /** ABAC: application-level approval state for this operation, resolved server-side. */
  approvalStatus?: "PENDING" | "APPROVED" | "REJECTED" | "EXECUTED";
  /** ABAC: advisory risk level from the security-intelligence engine (NEVER grants). */
  riskLevel?: "LOW" | "MEDIUM" | "HIGH";
  context?: { stepUpAuthenticated?: boolean; approvalRequired?: boolean };
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

    // ABAC (LOOP 4) — custody control: a TRANSFER moves custody, so the actor
    // must already hold it (or be an administrator performing asset
    // administration). Identity ids are resolved server-side; the client can
    // never assert custody.
    if (
      request.action === "TRANSFER" &&
      request.role !== "ADMIN" &&
      request.actorIdentityId &&
      request.currentCustodianIdentityId &&
      request.actorIdentityId !== request.currentCustodianIdentityId
    ) {
      return {
        decision: "DENY",
        decisionId,
        reason: "Only the current custodian (or an administrator) may transfer this asset",
        policyId: "POLICY-CUSTODY",
        timestamp,
      };
    }

    // ABAC — approval state: a rejected approval hard-blocks the operation;
    // an approval-gated operation without an APPROVED approval challenges.
    if (request.action === "TRANSFER" && request.approvalStatus === "REJECTED") {
      return {
        decision: "DENY",
        decisionId,
        reason: "The approval for this operation was rejected",
        policyId: "POLICY-APPROVAL-REJECTED",
        timestamp,
      };
    }
    if (
      request.action === "TRANSFER" &&
      request.context?.approvalRequired === true &&
      request.approvalStatus !== "APPROVED"
    ) {
      return {
        decision: "CHALLENGE",
        decisionId,
        reason: "An approved approval is required for this operation",
        policyId: "POLICY-APPROVAL",
        timestamp,
      };
    }

    // ABAC — advisory risk: security intelligence can ELEVATE a normally
    // allowed operation to a challenge for HIGH risk. It can NEVER grant —
    // every earlier DENY/CHALLENGE above already returned.
    if (
      request.riskLevel === "HIGH" &&
      (request.action === "TRANSFER" || request.action === "CREATE_ASSET")
    ) {
      return {
        decision: "CHALLENGE",
        decisionId,
        reason: "Advisory risk level is HIGH for this actor — additional verification required",
        policyId: "POLICY-RISK-ELEVATION",
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
