import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  countOpenAlerts,
  createAsset,
  createAuditEvent,
  createAuthorizationDecision,
  createDidRecord,
  createIdentity,
  getAssetById,
  getDb,
  getUserByOpenId,
  listAssets,
  listAuditEvents,
  listIdentities,
  listSecurityAlerts,
  upsertUser,
} from "./db";

// The db module lazily creates a drizzle instance only when DATABASE_URL is
// set. These tests exercise the documented no-database degradation paths.
const savedDatabaseUrl = process.env.DATABASE_URL;

beforeEach(() => {
  delete process.env.DATABASE_URL;
});

afterEach(() => {
  if (savedDatabaseUrl === undefined) {
    delete process.env.DATABASE_URL;
  } else {
    process.env.DATABASE_URL = savedDatabaseUrl;
  }
});

describe("db module without a configured database", () => {
  it("getDb resolves to null", async () => {
    await expect(getDb()).resolves.toBeNull();
  });

  it.each([
    ["listIdentities", listIdentities, []],
    ["listAssets", listAssets, []],
    ["listAuditEvents", () => listAuditEvents(), []],
    ["listSecurityAlerts", listSecurityAlerts, []],
  ])("%s degrades to an empty list", async (_name, fn, expected) => {
    if (_name === "listIdentities")
      await expect(listIdentities()).resolves.toEqual(expected);
    if (_name === "listAssets")
      await expect(listAssets()).resolves.toEqual(expected);
    if (_name === "listAuditEvents")
      await expect(listAuditEvents()).resolves.toEqual(expected);
    if (_name === "listSecurityAlerts")
      await expect(listSecurityAlerts()).resolves.toEqual(expected);
    void fn;
  });

  it("getUserByOpenId degrades to undefined", async () => {
    const warnSpy = vi
      .spyOn(console, "warn")
      .mockImplementation(() => undefined);
    try {
      await expect(getUserByOpenId("some-open-id")).resolves.toBeUndefined();
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining("Cannot get user")
      );
    } finally {
      warnSpy.mockRestore();
    }
  });

  it("upsertUser degrades to a warning without throwing", async () => {
    const warnSpy = vi
      .spyOn(console, "warn")
      .mockImplementation(() => undefined);
    try {
      await expect(
        upsertUser({ openId: "some-open-id", lastSignedIn: new Date() })
      ).resolves.toBeUndefined();
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining("Cannot upsert user")
      );
    } finally {
      warnSpy.mockRestore();
    }
  });

  it("upsertUser rejects an empty openId even without a database", async () => {
    await expect(upsertUser({ openId: "" })).rejects.toThrow(
      "User openId is required for upsert"
    );
  });

  it("countOpenAlerts degrades to 0", async () => {
    await expect(countOpenAlerts()).resolves.toBe(0);
  });

  it("getAssetById degrades to undefined", async () => {
    await expect(getAssetById("some-asset")).resolves.toBeUndefined();
  });

  it("createAuthorizationDecision degrades to undefined", async () => {
    await expect(
      createAuthorizationDecision({
        id: "decision-1",
        actorIdentityId: "actor-1",
        resourceType: "ASSET",
        resourceId: "ASSET-001",
        action: "TRANSFER",
        decision: "ALLOW",
        reason: "test",
        timestamp: new Date(),
      })
    ).resolves.toBeUndefined();
  });

  it("createAuditEvent degrades to undefined", async () => {
    await expect(
      createAuditEvent({
        actorIdentityId: "actor-1",
        action: "IDENTITY_CREATED",
        resourceType: "IDENTITY",
        resourceId: "identity-1",
      })
    ).resolves.toBeUndefined();
  });

  it("createIdentity throws when the database is not configured", async () => {
    await expect(
      createIdentity({
        displayName: "Aarav Mehta",
        organization: "SAMPRAAN",
        did: "did:web:demo",
      })
    ).rejects.toThrow("Database is not configured");
  });

  it("createAsset throws when the database is not configured", async () => {
    await expect(
      createAsset({
        assetId: "ASSET-001",
        name: "Demo",
        type: "DOCUMENT",
        classification: "CONTROLLED",
        ownerIdentityId: "owner-1",
        custodianIdentityId: "custodian-1",
      })
    ).rejects.toThrow("Database is not configured");
  });

  it("createDidRecord throws when the database is not configured", async () => {
    await expect(
      createDidRecord({
        identityId: "identity-1",
        did: "did:web:demo",
        method: "web",
        subject: "did:web:demo",
        document: {},
        status: "ACTIVE",
      })
    ).rejects.toThrow("Database is not configured");
  });
});
