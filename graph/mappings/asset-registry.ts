import {
  AssetRegistered,
  AssetAssigned,
  AssetTransferred,
  AssetStatusChanged,
} from "../generated/SampraanAssetRegistry/SampraanAssetRegistry";
import { Asset, AssetTransfer, BlockchainEvent } from "../generated/schema";

export const STATUS_NAMES = ["NONE", "PENDING", "ACTIVE", "SUSPENDED", "REVOKED"];

function eventId(txHash: string, logIndex: string): string {
  return `${txHash}-${logIndex}`;
}

export function handleAssetRegistered(event: AssetRegistered): void {
  const tokenId = event.params.tokenId.toString();
  let asset = Asset.load(tokenId);
  if (asset == null) {
    asset = new Asset(tokenId);
    asset.registeredAt = event.params.registeredAt;
  }
  asset.assetIdDigest = event.params.assetIdDigest;
  asset.classificationDigest = event.params.classificationDigest;
  asset.status = 1; // PENDING on register
  asset.custodian = event.params.custodian;
  asset.creator = event.params.custodian;
  asset.mintTransactionHash = event.transaction.hash;
  asset.mintBlockNumber = event.block.number;
  asset.mintedAt = event.params.registeredAt;
  asset.updatedAt = event.block.timestamp;
  asset.save();

  const transfer = new AssetTransfer(eventId(event.transaction.hash.toHexString(), event.logIndex.toString()));
  transfer.asset = tokenId;
  transfer.kind = "MINT";
  transfer.toCustodian = event.params.custodian;
  transfer.operator = event.transaction.from;
  transfer.transactionHash = event.transaction.hash;
  transfer.blockNumber = event.block.number;
  transfer.blockTimestamp = event.block.timestamp;
  transfer.save();

  const evt = new BlockchainEvent(eventId(event.transaction.hash.toHexString(), event.logIndex.toString()));
  evt.contract = "SampraanAssetRegistry";
  evt.eventName = "AssetRegistered";
  evt.blockNumber = event.block.number;
  evt.blockTimestamp = event.block.timestamp;
  evt.transactionHash = event.transaction.hash;
  evt.payload = `tokenId=${tokenId} custodian=${event.params.custodian.toHexString()}`;
  evt.save();
}

export function handleAssetAssigned(event: AssetAssigned): void {
  const tokenId = event.params.tokenId.toString();
  const asset = Asset.load(tokenId);
  if (asset != null) {
    asset.custodian = event.params.custodian;
    asset.updatedAt = event.params.assignedAt;
    asset.save();
  }
  const transfer = new AssetTransfer(eventId(event.transaction.hash.toHexString(), event.logIndex.toString()));
  transfer.asset = tokenId;
  transfer.kind = "ASSIGNMENT";
  transfer.toCustodian = event.params.custodian;
  transfer.operator = event.params.operator;
  transfer.transactionHash = event.transaction.hash;
  transfer.blockNumber = event.block.number;
  transfer.blockTimestamp = event.block.timestamp;
  transfer.save();
}

export function handleAssetTransferred(event: AssetTransferred): void {
  const tokenId = event.params.tokenId.toString();
  const asset = Asset.load(tokenId);
  if (asset != null) {
    asset.custodian = event.params.toCustodian;
    asset.updatedAt = event.params.transferredAt;
    asset.save();
  }
  const transfer = new AssetTransfer(eventId(event.transaction.hash.toHexString(), event.logIndex.toString()));
  transfer.asset = tokenId;
  transfer.kind = "TRANSFER";
  transfer.fromCustodian = event.params.fromCustodian;
  transfer.toCustodian = event.params.toCustodian;
  transfer.operator = event.params.operator;
  transfer.transactionHash = event.transaction.hash;
  transfer.blockNumber = event.block.number;
  transfer.blockTimestamp = event.block.timestamp;
  transfer.save();
}

export function handleAssetStatusChanged(event: AssetStatusChanged): void {
  const tokenId = event.params.tokenId.toString();
  const asset = Asset.load(tokenId);
  if (asset != null) {
    asset.status = event.params.newStatus;
    asset.updatedAt = event.params.changedAt;
    asset.save();
  }
  const evt = new BlockchainEvent(eventId(event.transaction.hash.toHexString(), event.logIndex.toString()));
  evt.contract = "SampraanAssetRegistry";
  evt.eventName = "AssetStatusChanged";
  evt.blockNumber = event.block.number;
  evt.blockTimestamp = event.block.timestamp;
  evt.transactionHash = event.transaction.hash;
  evt.payload = `tokenId=${tokenId} ${STATUS_NAMES[event.params.oldStatus]}->${STATUS_NAMES[event.params.newStatus]}`;
  evt.save();
}
