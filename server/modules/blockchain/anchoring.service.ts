/**
 * SAMPRAAN on-chain anchoring service (BUG-003 / QA finding #3).
 *
 * Identity and asset creation previously wrote ONLY to the read model
 * (MySQL). The Besu chain — the authoritative provenance/evidence layer —
 * never learned about them, so no IdentityRegistered / AssetRegistered
 * evidence existed for records the application itself created.
 *
 * Design decisions (verified against the live QBFT chain):
 *
 *  - Per-DID derived wallet: the identity contract keys identity records by
 *    wallet address. Anchoring every identity to the single operator wallet
 *    would make the second registration revert with AlreadyRegistered()
 *    (selector 0x3a81d6fc — observed live). We therefore derive a
 *    DETERMINISTIC wallet address per DID from the operator key
 *    (keccak256(keccak256(operatorKey), did)) so every SAMPRAAN identity
 *    gets its own stable on-chain reference wallet. The derivation never
 *    exposes the operator key and needs no signature authority — the
 *    operator still signs the registerIdentity transaction.
 *  - AlreadyRegistered() is treated as "already anchored" (idempotent),
 *    not as a failure.
 *  - Anchoring is BEST-EFFORT at the creation boundary: the database row is
 *    the source of truth for the application, and a chain outage must not
 *    make identity/asset creation impossible (fail-open for availability,
 *    never for authorization — the authorization path still requires the
 *    chain through authorizeTransfer).
 *  - Every attempt — success, skip or failure — is recorded as an audit
 *    event so operators can see and re-run pending anchors.
 *  - MOCK mode (no chain configured) records BLOCKCHAIN_ANCHOR_SKIPPED
 *    instead of pretending an anchor happened.
 */
import { keccak256, toUtf8Bytes, solidityPacked, Wallet } from "ethers";
import { createAuditEvent } from "../../db";
import { besuBlockchainService } from "./blockchain.service";
import type { TransactionEvidence } from "./blockchain.types";

export type AnchorOutcome =
  | { outcome: "ANCHORED"; evidence: TransactionEvidence }
  | { outcome: "SKIPPED"; reason: string }
  | { outcome: "FAILED"; reason: string };

export interface AnchorResult {
  outcome: AnchorOutcome["outcome"];
  walletAddress?: string;
  transactionHash?: string;
  blockNumber?: number;
  reason?: string;
}

/** Selector of the contracts' AlreadyRegistered() custom error. */
const ALREADY_REGISTERED_SELECTOR = "0x3a81d6fc";

function isAlreadyRegisteredError(reason: string): boolean {
  // ethers surfaces custom errors as "execution reverted (unknown custom
  // error)" with the selector embedded in the data field.
  return reason.includes(ALREADY_REGISTERED_SELECTOR) || /already registered/i.test(reason);
}

/**
 * Deterministically derive a stable on-chain reference wallet for a DID.
 * Purely derived from the operator key + DID; no separate secret is stored.
 */
export function deriveIdentityWallet(operatorKey: string, did: string): string {
  const seed = keccak256(
    solidityPacked(
      ["bytes32", "string"],
      [keccak256(toUtf8Bytes(operatorKey)), did]
    )
  );
  return new Wallet(seed).address;
}

async function persistAnchorAudit(input: {
  action: string;
  resourceId: string;
  result: AnchorResult;
  metadata?: Record<string, unknown>;
}): Promise<void> {
  const auditByOutcome: Record<AnchorResult["outcome"], string> = {
    ANCHORED: "BLOCKCHAIN_ANCHOR_CONFIRMED",
    SKIPPED: "BLOCKCHAIN_ANCHOR_SKIPPED",
    FAILED: "BLOCKCHAIN_ANCHOR_FAILED",
  };
  const decisionByOutcome: Record<AnchorResult["outcome"], "ALLOW" | "CHALLENGE" | "DENY"> = {
    ANCHORED: "ALLOW",
    SKIPPED: "CHALLENGE",
    FAILED: "DENY",
  };
  await createAuditEvent({
    actorIdentityId: null,
    action: auditByOutcome[input.result.outcome],
    resourceType: "IDENTITY_OR_ASSET",
    resourceId: input.resourceId,
    decision: decisionByOutcome[input.result.outcome],
    reason: input.result.reason ?? `On-chain anchor ${input.result.outcome.toLowerCase()}`,
    transactionHash: input.result.transactionHash ?? null,
    blockNumber: input.result.blockNumber ?? null,
    metadata: { source: "blockchain-anchoring", ...input.metadata },
  }).catch((error: unknown) => {
    // Evidence persistence failure must never break the primary operation,
    // but it must be visible in the server log.
    console.error("[Anchoring] Failed to persist anchor audit event:", error);
  });
}

export class AnchoringService {
  /**
   * Anchor a newly created SAMPRAAN identity on the Besu chain under a
   * deterministic per-DID reference wallet. Idempotent by construction.
   */
  async anchorIdentity(input: {
    did: string;
    displayName: string;
  }): Promise<AnchorResult> {
    if (!besuBlockchainService) {
      const result: AnchorResult = { outcome: "SKIPPED", reason: "Blockchain is not configured (MOCK mode); identity is not anchored on-chain" };
      await persistAnchorAudit({ action: "IDENTITY", resourceId: input.did, result });
      return result;
    }

    let result: AnchorResult;
    try {
      const operatorKey = this.requireOperatorKey();
      const walletAddress = deriveIdentityWallet(operatorKey, input.did);
      let evidence: TransactionEvidence;
      try {
        evidence = await besuBlockchainService.registerIdentity({
          did: input.did,
          walletAddress,
        });
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        if (isAlreadyRegisteredError(reason)) {
          // Same DID (digest) already anchored — this is an idempotent
          // re-creation in the read model, not a chain failure.
          const skipped: AnchorResult = { outcome: "SKIPPED", reason: `Identity ${input.did} is already anchored on-chain`, walletAddress };
          await persistAnchorAudit({ action: "IDENTITY", resourceId: input.did, result: skipped, metadata: { displayName: input.displayName } });
          return skipped;
        }
        throw error;
      }
      result = { outcome: "ANCHORED", walletAddress, transactionHash: evidence.transactionHash, blockNumber: evidence.blockNumber };
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      result = { outcome: "FAILED", reason };
    }
    await persistAnchorAudit({
      action: "IDENTITY",
      resourceId: input.did,
      result,
      metadata: { displayName: input.displayName },
    });
    return result;
  }

  /**
   * Anchor a newly created enterprise asset on the Besu chain (controlled
   * mint to the custodian). AssetAlreadyRegistered is an idempotent no-op.
   */
  async anchorAsset(input: {
    assetId: string;
    classification: string;
    integrityHash?: string | null;
  }): Promise<AnchorResult> {
    if (!besuBlockchainService) {
      const result: AnchorResult = { outcome: "SKIPPED", reason: "Blockchain is not configured (MOCK mode); asset is not anchored on-chain" };
      await persistAnchorAudit({ action: "ASSET", resourceId: input.assetId, result });
      return result;
    }

    let result: AnchorResult;
    try {
      const custodianWallet = besuBlockchainService.operatorAddress;
      const evidence = await besuBlockchainService.registerAsset({
        assetId: input.assetId,
        custodianWallet,
        classification: input.classification,
        metadataReference: input.integrityHash ?? `asset:${input.assetId}`,
      });
      result = { outcome: "ANCHORED", transactionHash: evidence.transactionHash, blockNumber: evidence.blockNumber };
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      if (isAlreadyRegisteredError(reason)) {
        result = { outcome: "SKIPPED", reason: `Asset ${input.assetId} is already anchored on-chain` };
      } else {
        result = { outcome: "FAILED", reason };
      }
    }
    await persistAnchorAudit({
      action: "ASSET",
      resourceId: input.assetId,
      result,
      metadata: { classification: input.classification },
    });
    return result;
  }

  private requireOperatorKey(): string {
    const config = besuBlockchainService?.config;
    if (!config?.privateKey) {
      throw new Error("Operator key is not configured; cannot derive identity wallets");
    }
    return config.privateKey;
  }
}

export const anchoringService = new AnchoringService();
