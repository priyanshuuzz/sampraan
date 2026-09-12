import {
  IdentityRegistered,
  IdentityStatusChanged,
} from "../generated/SampraanIdentityRegistry/SampraanIdentityRegistry";
import { Identity, BlockchainEvent } from "../generated/schema";

const IDENTITY_STATUS = ["NONE", "ACTIVE", "SUSPENDED", "REVOKED"];

function eventId(txHash: string, logIndex: string): string {
  return `${txHash}-${logIndex}`;
}

export function handleIdentityRegistered(event: IdentityRegistered): void {
  const wallet = event.params.wallet.toHexString();
  let identity = Identity.load(wallet);
  if (identity == null) {
    identity = new Identity(wallet);
    identity.registeredAt = event.params.registeredAt;
  }
  identity.wallet = event.params.wallet;
  identity.didDigest = event.params.didDigest;
  identity.status = 1; // ACTIVE
  identity.lastChangedAt = event.params.registeredAt;
  identity.lastTransactionHash = event.transaction.hash;
  identity.save();

  const evt = new BlockchainEvent(eventId(event.transaction.hash.toHexString(), event.logIndex.toString()));
  evt.contract = "SampraanIdentityRegistry";
  evt.eventName = "IdentityRegistered";
  evt.blockNumber = event.block.number;
  evt.blockTimestamp = event.block.timestamp;
  evt.transactionHash = event.transaction.hash;
  evt.payload = `wallet=${wallet} didDigest=${event.params.didDigest.toHexString()}`;
  evt.save();
}

export function handleIdentityStatusChanged(event: IdentityStatusChanged): void {
  const wallet = event.params.wallet.toHexString();
  const identity = Identity.load(wallet);
  if (identity != null) {
    identity.status = event.params.newStatus;
    identity.lastChangedAt = event.params.changedAt;
    identity.lastTransactionHash = event.transaction.hash;
    identity.save();
  }
  const evt = new BlockchainEvent(eventId(event.transaction.hash.toHexString(), event.logIndex.toString()));
  evt.contract = "SampraanIdentityRegistry";
  evt.eventName = "IdentityStatusChanged";
  evt.blockNumber = event.block.number;
  evt.blockTimestamp = event.block.timestamp;
  evt.transactionHash = event.transaction.hash;
  evt.payload = `wallet=${wallet} ${IDENTITY_STATUS[event.params.oldStatus]}->${IDENTITY_STATUS[event.params.newStatus]}`;
  evt.save();
}
