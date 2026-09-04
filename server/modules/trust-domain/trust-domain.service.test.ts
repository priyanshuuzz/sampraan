import { describe, expect, it } from "vitest";
import { TrustDomainService } from "./trust-domain.service";

describe("TrustDomainService", () => {
  it("creates and retrieves an identity", () => {
    const service = new TrustDomainService();
    const identity = service.createIdentity({
      displayName: "Aarav Mehta",
      did: "did:demo:aarav",
      status: "ACTIVE",
    });
    expect(service.getIdentity(identity.id)).toMatchObject({
      displayName: "Aarav Mehta",
      did: "did:demo:aarav",
    });
  });

  it("assigns a role and records the audit event", () => {
    const service = new TrustDomainService();
    const identity = service.createIdentity({
      displayName: "Ananya Rao",
      did: "did:demo:ananya",
      status: "ACTIVE",
    });
    service.assignRole(identity.id, "MANAGER");
    expect(service.getIdentity(identity.id)?.roles).toContain("MANAGER");
    expect(service.audit.at(-1)).toMatchObject({
      action: "ROLE_ASSIGNED",
      decision: "ALLOW",
    });
  });

  it("registers an asset and separates owner from custodian", () => {
    const service = new TrustDomainService();
    const owner = service.createIdentity({
      displayName: "Aarav Mehta",
      did: "did:demo:owner",
      status: "ACTIVE",
    });
    const custodian = service.createIdentity({
      displayName: "Ananya Rao",
      did: "did:demo:custodian",
      status: "ACTIVE",
    });
    const asset = service.registerAsset({
      assetId: "ASSET-001",
      classification: "CONTROLLED",
      ownerIdentityId: owner.id,
      custodianIdentityId: owner.id,
    });
    service.assignAsset(asset.id, custodian.id);
    expect(asset.ownerIdentityId).toBe(owner.id);
    expect(service.assets.get(asset.id)?.custodianIdentityId).toBe(
      custodian.id
    );
  });

  it("denies an unauthorized highly sensitive transfer without changing custody", () => {
    const service = new TrustDomainService();
    const owner = service.createIdentity({
      displayName: "Aarav Mehta",
      did: "did:demo:owner2",
      status: "ACTIVE",
    });
    const user = service.createIdentity({
      displayName: "Vikram Singh",
      did: "did:demo:user",
      status: "ACTIVE",
    });
    const asset = service.registerAsset({
      assetId: "ASSET-HIGH-001",
      classification: "HIGHLY_SENSITIVE",
      ownerIdentityId: owner.id,
      custodianIdentityId: owner.id,
    });
    const result = service.transferAsset(asset.id, user.id, "USER", [
      "asset:transfer",
    ]);
    expect(result.decision).toBe("DENY");
    expect(service.assets.get(asset.id)?.custodianIdentityId).toBe(owner.id);
    expect(service.audit.at(-1)).toMatchObject({
      action: "AUTHORIZATION_DENIED",
      decision: "DENY",
    });
  });

  it("allows an admin transfer and records an allow audit event", () => {
    const service = new TrustDomainService();
    const owner = service.createIdentity({
      displayName: "Aarav Mehta",
      did: "did:demo:owner3",
      status: "ACTIVE",
    });
    const admin = service.createIdentity({
      displayName: "Admin Operator",
      did: "did:demo:admin",
      status: "ACTIVE",
    });
    const asset = service.registerAsset({
      assetId: "ASSET-002",
      classification: "CONTROLLED",
      ownerIdentityId: owner.id,
      custodianIdentityId: owner.id,
    });
    const result = service.transferAsset(asset.id, admin.id, "ADMIN", [
      "asset:transfer",
    ]);
    expect(result.decision).toBe("ALLOW");
    expect(service.assets.get(asset.id)?.custodianIdentityId).toBe(admin.id);
    expect(
      service.audit.some(event => event.action === "AUTHORIZATION_ALLOWED")
    ).toBe(true);
  });

  it("denies a revoked identity", () => {
    const service = new TrustDomainService();
    const owner = service.createIdentity({
      displayName: "Aarav Mehta",
      did: "did:demo:owner4",
      status: "ACTIVE",
    });
    const revoked = service.createIdentity({
      displayName: "Revoked Operator",
      did: "did:demo:revoked",
      status: "REVOKED",
    });
    const asset = service.registerAsset({
      assetId: "ASSET-003",
      classification: "CONTROLLED",
      ownerIdentityId: owner.id,
      custodianIdentityId: owner.id,
    });
    expect(
      service.transferAsset(asset.id, revoked.id, "ADMIN", ["asset:transfer"])
        .decision
    ).toBe("DENY");
  });

  it("denies a suspended identity", () => {
    const service = new TrustDomainService();
    const owner = service.createIdentity({
      displayName: "Aarav Mehta",
      did: "did:demo:owner5",
      status: "ACTIVE",
    });
    const suspended = service.createIdentity({
      displayName: "Suspended Operator",
      did: "did:demo:suspended",
      status: "SUSPENDED",
    });
    const asset = service.registerAsset({
      assetId: "ASSET-004",
      classification: "CONTROLLED",
      ownerIdentityId: owner.id,
      custodianIdentityId: owner.id,
    });
    const result = service.transferAsset(asset.id, suspended.id, "ADMIN", [
      "asset:transfer",
    ]);
    expect(result.decision).toBe("DENY");
    expect(service.assets.get(asset.id)?.custodianIdentityId).toBe(owner.id);
  });

  it("denies an unknown actor by treating them as non-ACTIVE", () => {
    const service = new TrustDomainService();
    const owner = service.createIdentity({
      displayName: "Aarav Mehta",
      did: "did:demo:owner6",
      status: "ACTIVE",
    });
    const asset = service.registerAsset({
      assetId: "ASSET-005",
      classification: "CONTROLLED",
      ownerIdentityId: owner.id,
      custodianIdentityId: owner.id,
    });
    // The actor identity does not exist in the trust domain.
    const result = service.transferAsset(
      asset.id,
      "missing-identity-id",
      "ADMIN",
      ["asset:transfer"]
    );
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("Identity is suspended");
    expect(service.assets.get(asset.id)?.custodianIdentityId).toBe(owner.id);
  });

  it("challenges an admin highly sensitive transfer without step-up and keeps custody", () => {
    const service = new TrustDomainService();
    const owner = service.createIdentity({
      displayName: "Aarav Mehta",
      did: "did:demo:owner7",
      status: "ACTIVE",
    });
    const admin = service.createIdentity({
      displayName: "Admin Operator",
      did: "did:demo:admin2",
      status: "ACTIVE",
    });
    const asset = service.registerAsset({
      assetId: "ASSET-HIGH-002",
      classification: "HIGHLY_SENSITIVE",
      ownerIdentityId: owner.id,
      custodianIdentityId: owner.id,
    });
    const result = service.transferAsset(asset.id, admin.id, "ADMIN", [
      "asset:transfer",
    ]);
    expect(result.decision).toBe("CHALLENGE");
    expect(result.policyId).toBe("POLICY-STEP-UP");
    expect(service.assets.get(asset.id)?.custodianIdentityId).toBe(owner.id);
    expect(service.audit.at(-1)).toMatchObject({
      action: "AUTHORIZATION_CHALLENGED",
      decision: "CHALLENGE",
    });
  });

  it("allows an admin highly sensitive transfer after step-up is granted by the engine", () => {
    const service = new TrustDomainService();
    const owner = service.createIdentity({
      displayName: "Aarav Mehta",
      did: "did:demo:owner8",
      status: "ACTIVE",
    });
    const admin = service.createIdentity({
      displayName: "Admin Operator",
      did: "did:demo:admin3",
      status: "ACTIVE",
    });
    const asset = service.registerAsset({
      assetId: "ASSET-HIGH-003",
      classification: "HIGHLY_SENSITIVE",
      ownerIdentityId: owner.id,
      custodianIdentityId: owner.id,
    });
    // The trust-domain transferAsset path does not forward step-up context;
    // engine-level step-up behaviour is covered in authorization.service.test.ts.
    const result = service.transferAsset(asset.id, admin.id, "ADMIN", [
      "asset:transfer",
    ]);
    expect(result.decision).toBe("CHALLENGE");
  });

  it("denies a role that lacks the transfer permission", () => {
    const service = new TrustDomainService();
    const owner = service.createIdentity({
      displayName: "Aarav Mehta",
      did: "did:demo:owner9",
      status: "ACTIVE",
    });
    const viewer = service.createIdentity({
      displayName: "Viewer",
      did: "did:demo:viewer",
      status: "ACTIVE",
    });
    const asset = service.registerAsset({
      assetId: "ASSET-006",
      classification: "CONTROLLED",
      ownerIdentityId: owner.id,
      custodianIdentityId: owner.id,
    });
    const result = service.transferAsset(asset.id, viewer.id, "VIEWER", [
      "asset:read",
    ]);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("Role VIEWER does not hold asset:transfer");
  });

  it("throws for an unknown asset on transfer", () => {
    const service = new TrustDomainService();
    const actor = service.createIdentity({
      displayName: "Actor",
      did: "did:demo:actor",
      status: "ACTIVE",
    });
    expect(() =>
      service.transferAsset("missing-asset", actor.id, "ADMIN", [])
    ).toThrow("Asset not found");
  });

  it("throws for an unknown asset on custody assignment", () => {
    const service = new TrustDomainService();
    const custodian = service.createIdentity({
      displayName: "Custodian",
      did: "did:demo:custodian2",
      status: "ACTIVE",
    });
    expect(() => service.assignAsset("missing-asset", custodian.id)).toThrow(
      "Asset not found"
    );
  });

  it("throws when assigning a role to an unknown identity", () => {
    const service = new TrustDomainService();
    expect(() => service.assignRole("missing-identity", "MANAGER")).toThrow(
      "Identity not found"
    );
  });

  it("does not change custody on CHALLENGE", () => {
    const service = new TrustDomainService();
    const owner = service.createIdentity({
      displayName: "Aarav Mehta",
      did: "did:demo:owner10",
      status: "ACTIVE",
    });
    const manager = service.createIdentity({
      displayName: "Manager",
      did: "did:demo:manager",
      status: "ACTIVE",
    });
    const asset = service.registerAsset({
      assetId: "ASSET-007",
      classification: "HIGHLY_SENSITIVE",
      ownerIdentityId: owner.id,
      custodianIdentityId: owner.id,
    });
    const result = service.transferAsset(asset.id, manager.id, "MANAGER", [
      "asset:transfer",
    ]);
    expect(result.decision).toBe("CHALLENGE");
    expect(service.assets.get(asset.id)?.custodianIdentityId).toBe(owner.id);
  });

  it("records an audit event for every lifecycle action", () => {
    const service = new TrustDomainService();
    const owner = service.createIdentity({
      displayName: "Aarav Mehta",
      did: "did:demo:owner11",
      status: "ACTIVE",
    });
    const custodian = service.createIdentity({
      displayName: "Ananya Rao",
      did: "did:demo:custodian3",
      status: "ACTIVE",
    });
    service.assignRole(owner.id, "ADMIN");
    const asset = service.registerAsset({
      assetId: "ASSET-008",
      classification: "CONTROLLED",
      ownerIdentityId: owner.id,
      custodianIdentityId: owner.id,
    });
    service.assignAsset(asset.id, custodian.id);
    service.transferAsset(asset.id, owner.id, "ADMIN", ["asset:transfer"]);

    const actions = service.audit.map(event => event.action);
    expect(actions).toEqual([
      "IDENTITY_CREATED",
      "IDENTITY_CREATED",
      "ROLE_ASSIGNED",
      "ASSET_REGISTERED",
      "CUSTODY_ASSIGNED",
      "AUTHORIZATION_ALLOWED",
    ]);
    // Every audit event carries an id and a parseable timestamp.
    for (const event of service.audit) {
      expect(event.id).toMatch(/[0-9a-f-]{36}/);
      expect(Number.isNaN(Date.parse(event.timestamp))).toBe(false);
    }
  });

  it("allows a MANAGER with the transfer permission for a controlled asset", () => {
    const service = new TrustDomainService();
    const owner = service.createIdentity({
      displayName: "Aarav Mehta",
      did: "did:demo:owner12",
      status: "ACTIVE",
    });
    const manager = service.createIdentity({
      displayName: "Manager",
      did: "did:demo:manager2",
      status: "ACTIVE",
    });
    const asset = service.registerAsset({
      assetId: "ASSET-009",
      classification: "CONTROLLED",
      ownerIdentityId: owner.id,
      custodianIdentityId: owner.id,
    });
    const result = service.transferAsset(asset.id, manager.id, "MANAGER", [
      "asset:transfer",
    ]);
    expect(result.decision).toBe("ALLOW");
    expect(service.assets.get(asset.id)?.custodianIdentityId).toBe(manager.id);
  });
});
