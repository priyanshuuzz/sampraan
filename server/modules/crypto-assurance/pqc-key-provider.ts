/**
 * SAMPRAAN PQC key provider — the seam between the assurance layer and HOW a
 * DID's ML-DSA-65 key material is held.
 *
 * Two providers exist, and the difference is a SECURITY boundary, not a
 * convenience flag:
 *
 *  - RegisteredKeyProvider (production posture)
 *      Resolves the ACTIVE public key the holder registered through
 *      `assurance.key.register` (which requires a signed proof of possession).
 *      There is NO signing capability and NO derivation fallback: if a DID has
 *      no registered PQC key, the assurance layer fails CLOSED and the
 *      protected operation requires a key to be registered first. This is the
 *      only provider that may be used in production.
 *
 *  - LocalDevPqcKeyProvider (LOCAL DEMO ONLY)
 *      Derives a deterministic ML-DSA-65 keypair from the server operator key
 *      + DID, exactly mirroring the ECDSA `LocalDevDidKeyProvider`
 *      (did-key-provider.ts) so the demo can be exercised end-to-end without
 *      shipping key material. Registered keys STILL take precedence. Rotation
 *      generation is folded into the derivation seed, so rotate → new key.
 *
 * Selected by the PQC_KEY_PROVIDER environment variable:
 *   "local-dev"  → dev provider (default outside production)
 *   "registered" → production provider (default IN production)
 * Crossing the boundary is explicit: setting "local-dev" in production is
 * logged as a SECURITY warning on every boot and is refused outright when
 * PQC_ALLOW_DEV_KEYS_IN_PRODUCTION is not "1", so an insecure deployment
 * cannot happen by accident.
 */
import { keccak256, solidityPacked, toUtf8Bytes } from "ethers";
import { getActivePqcKeyRecord } from "../../db";
import { ML_DSA_65_ALGORITHM, fingerprintPublicKey, encodeBase64Url, keyPairFromSeed, pqcKeyIdentifierFor, signMessage } from "./ml-dsa";

export type PqcKeySource = "REGISTERED" | "SERVER_DERIVED";

export interface ResolvedPqcKey {
  did: string;
  keyIdentifier: string;
  algorithm: typeof ML_DSA_65_ALGORITHM;
  publicKey: string;
  publicKeyFingerprint: string;
  keySource: PqcKeySource;
}

export interface PqcKeyProvider {
  readonly name: string;
  /** Resolve the ACTIVE verification key for a DID, or null (fail closed). */
  resolvePublicKey(did: string): Promise<ResolvedPqcKey | null>;
  /**
   * Sign with the DID's key — DEV-ONLY. A production provider returns null;
   * the verification path never needs it (the holder signs client-side).
   */
  signWithDerivedKey(did: string, message: string): Promise<string | null>;
}

function isProduction(): boolean {
  return process.env.NODE_ENV === "production";
}

/**
 * Derive the deterministic ML-DSA-65 keypair for a DID.
 *
 * seed = keccak256( keccak256(operatorKey) || did )  — 32 bytes, the size
 * ML-DSA-65 keygen requires. Identical in shape to the ECDSA reference wallet
 * derivation, so the demo credential is reproducible but NEVER stored.
 */
export function derivePqcKeyPair(operatorKey: string, did: string): { publicKey: Uint8Array; secretKey: Uint8Array } {
  if (!/^0x[0-9a-fA-F]{64}$/.test(operatorKey)) {
    throw new Error("PQC key derivation requires a valid 32-byte hex operator key");
  }
  const seed = keccak256(solidityPacked(["bytes32", "string"], [keccak256(toUtf8Bytes(operatorKey)), `${did}#ml-dsa-65`]));
  const seedBytes = Buffer.from(seed.slice(2), "hex");
  return keyPairFromSeed(new Uint8Array(seedBytes));
}

class RegisteredKeyProvider implements PqcKeyProvider {
  readonly name = "registered";

  async resolvePublicKey(did: string): Promise<ResolvedPqcKey | null> {
    const record = await getActivePqcKeyRecord(did);
    if (!record) return null;
    return {
      did: record.did,
      keyIdentifier: record.keyIdentifier,
      algorithm: ML_DSA_65_ALGORITHM,
      publicKey: record.publicKey,
      publicKeyFingerprint: record.publicKeyFingerprint,
      keySource: record.keySource as PqcKeySource,
    };
  }

  async signWithDerivedKey(): Promise<string | null> {
    // A registered key's secret half is held by the holder — by definition the
    // server cannot sign with it.
    return null;
  }
}

class LocalDevPqcKeyProvider implements PqcKeyProvider {
  readonly name = "local-dev";
  private readonly registered = new RegisteredKeyProvider();

  constructor(private readonly operatorKey: string) {
    if (!/^0x[0-9a-fA-F]{64}$/.test(operatorKey)) {
      throw new Error("LocalDevPqcKeyProvider requires a valid 32-byte hex operator key");
    }
  }

  async resolvePublicKey(did: string): Promise<ResolvedPqcKey | null> {
    // A holder-registered key always wins: the demo must not be able to bypass
    // a real registration.
    const registered = await this.registered.resolvePublicKey(did);
    if (registered) return registered;

    const { publicKey } = derivePqcKeyPair(this.operatorKey, did);
    return {
      did,
      keyIdentifier: pqcKeyIdentifierFor(did, 1),
      algorithm: ML_DSA_65_ALGORITHM,
      publicKey: encodeBase64Url(publicKey),
      publicKeyFingerprint: fingerprintPublicKey(publicKey),
      keySource: "SERVER_DERIVED",
    };
  }

  async signWithDerivedKey(did: string, message: string): Promise<string | null> {
    const { secretKey } = derivePqcKeyPair(this.operatorKey, did);
    const signature = signMessage(message, secretKey);
    return signature ? encodeBase64Url(signature) : null;
  }
}

/** Human-readable description of the ACTIVE provider (surfaced by /ready + UI). */
export function describePqcProvider(): { provider: string; postQuantum: "DEV_DERIVED" | "REGISTERED_ONLY"; productionSafe: boolean } {
  const provider = resolvePqcKeyProvider();
  return {
    provider: provider.name,
    postQuantum: provider.name === "local-dev" ? "DEV_DERIVED" : "REGISTERED_ONLY",
    productionSafe: provider.name === "registered",
  };
}

export function resolvePqcKeyProvider(): PqcKeyProvider {
  const requested = (process.env.PQC_KEY_PROVIDER ?? "").trim().toLowerCase();
  const operatorKey = process.env.PQC_PRIVATE_KEY ?? process.env.BLOCKCHAIN_PRIVATE_KEY ?? "";

  if (requested === "local-dev") {
    if (isProduction() && process.env.PQC_ALLOW_DEV_KEYS_IN_PRODUCTION !== "1") {
      console.error(
        "[Security] PQC_KEY_PROVIDER=local-dev is refused in production: server-derived PQC keys are not a production key-management strategy. Set PQC_KEY_PROVIDER=registered (recommended) or, for a deliberate demo deployment only, PQC_ALLOW_DEV_KEYS_IN_PRODUCTION=1.",
      );
      return new RegisteredKeyProvider();
    }
    if (isProduction()) {
      console.warn("[Security] PQC_KEY_PROVIDER=local-dev active in production — ML-DSA-65 keys are server-derived demo material, NOT holder-held keys.");
    }
    return operatorKey ? new LocalDevPqcKeyProvider(operatorKey) : new RegisteredKeyProvider();
  }

  if (requested === "registered") return new RegisteredKeyProvider();

  // Unset → environment default. Outside production the demo provider keeps the
  // local flow working; in production we always fail closed to registered keys.
  if (!isProduction() && operatorKey) return new LocalDevPqcKeyProvider(operatorKey);
  return new RegisteredKeyProvider();
}

export { RegisteredKeyProvider, LocalDevPqcKeyProvider };
