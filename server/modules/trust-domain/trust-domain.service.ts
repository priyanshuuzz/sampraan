import { randomUUID } from "node:crypto";
import {
  authorizationService,
  type AuthorizationResult,
} from "../authorization/authorization.service";

/**
 * In-memory SAMPRAAN trust-domain model (identities, roles, assets, custody,
 * audit trail) used by the deterministic SIH demo narrative and tests.
 *
 * Transfer decisions delegate to the shared authorizationService so there is a
 * single backend policy engine — this class never grants access on its own.
 */

export type TrustDomainIdentityStatus = "ACTIVE" | "REVOKED" | "SUSPENDED";

export interface TrustDomainIdentity {
  id: string;
  displayName: string;
  did: string;
  status: TrustDomainIdentityStatus;
  roles: string[];
}

export interface TrustDomainAsset {
  id: string;
  assetId: string;
  classification: string;
  ownerIdentityId: string;
  custodianIdentityId: string;
}

export interface TrustDomainAuditEvent {
  id: string;
  actorIdentityId: string | null;
  action: string;
  resourceType: string;
  resourceId: string;
  decision: string;
  reason: string;
  timestamp: string;
}

function auditActionForDecision(decision: AuthorizationResult["decision"]) {
  if (decision === "DENY") return "AUTHORIZATION_DENIED";
  if (decision === "CHALLENGE") return "AUTHORIZATION_CHALLENGED";
  return "AUTHORIZATION_ALLOWED";
}

export class TrustDomainService {
  identities = new Map<string, TrustDomainIdentity>();
  assets = new Map<string, TrustDomainAsset>();
  audit: TrustDomainAuditEvent[] = [];

  createIdentity(input: {
    displayName: string;
    did: string;
    status: TrustDomainIdentityStatus;
  }): TrustDomainIdentity {
    const identity: TrustDomainIdentity = {
      id: randomUUID(),
      displayName: input.displayName,
      did: input.did,
      status: input.status,
      roles: [],
    };
    this.identities.set(identity.id, identity);
    this.recordAudit({
      actorIdentityId: identity.id,
      action: "IDENTITY_CREATED",
      resourceType: "IDENTITY",
      resourceId: identity.id,
      decision: "ALLOW",
      reason: "Identity registered in the trust domain",
    });
    return identity;
  }

  getIdentity(id: string): TrustDomainIdentity | undefined {
    return this.identities.get(id);
  }

  assignRole(identityId: string, role: string): void {
    const identity = this.identities.get(identityId);
    if (!identity) throw new Error("Identity not found");
    identity.roles.push(role);
    this.recordAudit({
      actorIdentityId: identityId,
      action: "ROLE_ASSIGNED",
      resourceType: "IDENTITY",
      resourceId: identityId,
      decision: "ALLOW",
      reason: `Role ${role} assigned to ${identity.displayName}`,
    });
  }

  registerAsset(input: {
    assetId: string;
    classification: string;
    ownerIdentityId: string;
    custodianIdentityId: string;
  }): TrustDomainAsset {
    const asset: TrustDomainAsset = {
      id: randomUUID(),
      assetId: input.assetId,
      classification: input.classification,
      ownerIdentityId: input.ownerIdentityId,
      custodianIdentityId: input.custodianIdentityId,
    };
    this.assets.set(asset.id, asset);
    this.recordAudit({
      actorIdentityId: input.ownerIdentityId,
      action: "ASSET_REGISTERED",
      resourceType: "ASSET",
      resourceId: asset.assetId,
      decision: "ALLOW",
      reason: "Asset registered with separated ownership and custody",
    });
    return asset;
  }

  assignAsset(assetId: string, custodianIdentityId: string): void {
    const asset = this.assets.get(assetId);
    if (!asset) throw new Error("Asset not found");
    asset.custodianIdentityId = custodianIdentityId;
    this.recordAudit({
      actorIdentityId: custodianIdentityId,
      action: "CUSTODY_ASSIGNED",
      resourceType: "ASSET",
      resourceId: asset.assetId,
      decision: "ALLOW",
      reason: "Custody assigned to a verified identity",
    });
  }

  /**
   * Evaluates a custody transfer through the shared backend authorization
   * engine. Custody only changes when the engine returns ALLOW.
   */
  transferAsset(
    assetId: string,
    actorIdentityId: string,
    role: string,
    permissions: string[]
  ): AuthorizationResult {
    const asset = this.assets.get(assetId);
    if (!asset) throw new Error("Asset not found");
    const identity = this.identities.get(actorIdentityId);

    const result = authorizationService.evaluate({
      // Unknown actors must never evaluate as ACTIVE.
      identityStatus: identity?.status ?? "SUSPENDED",
      role,
      permissions,
      resourceType: "asset",
      action: "TRANSFER",
      assetClassification: asset.classification,
    });

    if (result.decision === "ALLOW") {
      asset.custodianIdentityId = actorIdentityId;
    }

    this.recordAudit({
      actorIdentityId,
      action: auditActionForDecision(result.decision),
      resourceType: "ASSET",
      resourceId: asset.assetId,
      decision: result.decision,
      reason: result.reason,
    });

    return result;
  }

  private recordAudit(event: Omit<TrustDomainAuditEvent, "id" | "timestamp">) {
    this.audit.push({
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      ...event,
    });
  }
}
