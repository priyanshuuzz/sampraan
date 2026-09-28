/**
 * SAMPRAAN DID key provider abstraction.
 *
 * Separate concern from storage: this module owns HOW the private key
 * material backing a DID's verification method is held and used.
 *
 * Production requirement: the application must never be tightly coupled to
 * plaintext private-key handling. Everything that needs signing goes through
 * this interface, so a KMS/HSM implementation (AWS KMS, Azure Key Vault,
 * CloudHSM, Vault Transit) can replace the dev provider by configuration —
 * the DID authentication code does not change.
 *
 * IMPLEMENTED TODAY: LocalDevDidKeyProvider (deterministic dev derivation).
 * NOT implemented (do not claim otherwise): actual HSM/KMS integration.
 * The interface below is the KMS/HSM seam.
 */
import { keccak256, solidityPacked, toUtf8Bytes, Wallet } from "ethers";

/** Context passed to every signing operation (for KMS audit metadata). */
export interface DidSigningContext {
  did: string;
  keyIdentifier: string;
  purpose: string;
}

export interface DidKeyProvider {
  readonly name: string;
  /**
   * Sign a message for a DID's current verification key. Implementations
   * MUST NOT return or expose private key material in any result.
   */
  sign(context: DidSigningContext, message: string): Promise<string>;
  /**
   * Public address that signatures for this DID's current key MUST recover
   * to. For the deterministic provider this equals deriveIdentityWallet();
   * a KMS provider would return the KMS-held key's address.
   */
  expectedAddress(context: DidSigningContext): Promise<string> | string;
}

/**
 * DEVELOPMENT provider (LOCAL DEMO ONLY).
 *
 * Deterministically derives each DID's signing seed from the operator key
 * + DID string — the SAME derivation the on-chain anchoring uses
 * (deriveIdentityWallet). This is what makes the demo work end-to-end
 * without shipping key material: the "holder" of a DID key is anyone who
 * legitimately derives the seed client-side, and the server only ever
 * verifies (it can derive the expected ADDRESS, never needs the key).
 *
 * SECURITY TRUTH (documented, not hidden):
 *  - This is equivalent to a per-DID deterministic wallet derived from a
 *    server-side master. It is NOT an HSM. It does not attempt to hide the
 *    derivation from the honest demo client.
 *  - A production deployment MUST swap this for a KMS/HSM-backed provider:
 *    keys generated inside the KMS, signing via KMS API, private material
 *    never existing outside the boundary. The interface supports that
 *    without touching authentication code.
 */
export class LocalDevDidKeyProvider implements DidKeyProvider {
  readonly name = "local-dev-derived";

  constructor(private readonly operatorKey: string) {
    if (!operatorKey || !/^0x[0-9a-fA-F]{64}$/.test(operatorKey)) {
      throw new Error("LocalDevDidKeyProvider requires a valid 32-byte hex operator key");
    }
  }

  static fromEnvironment(): LocalDevDidKeyProvider | null {
    const key = process.env.BLOCKCHAIN_PRIVATE_KEY;
    return key ? new LocalDevDidKeyProvider(key) : null;
  }

  private seed(did: string): string {
    return keccak256(solidityPacked(["bytes32", "string"], [keccak256(toUtf8Bytes(this.operatorKey)), did]));
  }

  async sign(context: DidSigningContext, message: string): Promise<string> {
    return new Wallet(this.seed(context.did)).signMessage(message);
  }

  expectedAddress(context: DidSigningContext): string {
    return new Wallet(this.seed(context.did)).address;
  }
}

/** Resolve the configured provider (single seam — swap here for KMS). */
export function resolveDidKeyProvider(): DidKeyProvider | null {
  return LocalDevDidKeyProvider.fromEnvironment();
}
