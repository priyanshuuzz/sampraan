import { describe, expect, it } from "vitest";
import { TrustDomainService } from "./trust-domain.service";

describe("TrustDomainService", () => {
  it("creates and retrieves an identity", () => {
    const service = new TrustDomainService();
    const identity = service.createIdentity({ displayName: "Aarav Mehta", did: "did:demo:aarav", status: "ACTIVE" });
    expect(service.getIdentity(identity.id)).toMatchObject({ displayName: "Aarav Mehta", did: "did:demo:aarav" });
  });

  it("assigns a role and records the audit event", () => {
    const service = new TrustDomainService();
    const identity = service.createIdentity({ displayName: "Ananya Rao", did: "did:demo:ananya", status: "ACTIVE" });
    service.assignRole(identity.id, "MANAGER");
    expect(service.getIdentity(identity.id)?.roles).toContain("MANAGER");
    expect(service.audit.at(-1)).toMatchObject({ action: "ROLE_ASSIGNED", decision: "ALLOW" });
  });

  it("registers an asset and separates owner from custodian", () => {
    const service = new TrustDomainService();
    const owner = service.createIdentity({ displayName: "Aarav Mehta", did: "did:demo:owner", status: "ACTIVE" });
    const custodian = service.createIdentity({ displayName: "Ananya Rao", did: "did:demo:custodian", status: "ACTIVE" });
    const asset = service.registerAsset({ assetId: "ASSET-001", classification: "CONTROLLED", ownerIdentityId: owner.id, custodianIdentityId: owner.id });
    service.assignAsset(asset.id, custodian.id);
    expect(asset.ownerIdentityId).toBe(owner.id);
    expect(service.assets.get(asset.id)?.custodianIdentityId).toBe(custodian.id);
  });

  it("denies an unauthorized highly sensitive transfer without changing custody", () => {
    const service = new TrustDomainService();
    const owner = service.createIdentity({ displayName: "Aarav Mehta", did: "did:demo:owner2", status: "ACTIVE" });
    const user = service.createIdentity({ displayName: "Vikram Singh", did: "did:demo:user", status: "ACTIVE" });
    const asset = service.registerAsset({ assetId: "ASSET-HIGH-001", classification: "HIGHLY_SENSITIVE", ownerIdentityId: owner.id, custodianIdentityId: owner.id });
    const result = service.transferAsset(asset.id, user.id, "USER", ["asset:transfer"]);
    expect(result.decision).toBe("DENY");
    expect(service.assets.get(asset.id)?.custodianIdentityId).toBe(owner.id);
    expect(service.audit.at(-1)).toMatchObject({ action: "AUTHORIZATION_DENIED", decision: "DENY" });
  });

  it("allows an admin transfer and records an allow audit event", () => {
    const service = new TrustDomainService();
    const owner = service.createIdentity({ displayName: "Aarav Mehta", did: "did:demo:owner3", status: "ACTIVE" });
    const admin = service.createIdentity({ displayName: "Admin Operator", did: "did:demo:admin", status: "ACTIVE" });
    const asset = service.registerAsset({ assetId: "ASSET-002", classification: "CONTROLLED", ownerIdentityId: owner.id, custodianIdentityId: owner.id });
    const result = service.transferAsset(asset.id, admin.id, "ADMIN", ["asset:transfer"]);
    expect(result.decision).toBe("ALLOW");
    expect(service.assets.get(asset.id)?.custodianIdentityId).toBe(admin.id);
    expect(service.audit.some(event => event.action === "AUTHORIZATION_ALLOWED")).toBe(true);
  });

  it("denies a revoked identity", () => {
    const service = new TrustDomainService();
    const owner = service.createIdentity({ displayName: "Aarav Mehta", did: "did:demo:owner4", status: "ACTIVE" });
    const revoked = service.createIdentity({ displayName: "Revoked Operator", did: "did:demo:revoked", status: "REVOKED" });
    const asset = service.registerAsset({ assetId: "ASSET-003", classification: "CONTROLLED", ownerIdentityId: owner.id, custodianIdentityId: owner.id });
    expect(service.transferAsset(asset.id, revoked.id, "ADMIN", ["asset:transfer"]).decision).toBe("DENY");
  });
});
