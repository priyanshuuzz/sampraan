import { RoleGranted, RoleRevoked } from "../generated/SampraanAccessControl/SampraanAccessControl";
import { BlockchainEvent } from "../generated/schema";

function eventId(txHash: string, logIndex: string): string {
  return `${txHash}-${logIndex}`;
}

export function handleRoleGranted(event: RoleGranted): void {
  const evt = new BlockchainEvent(eventId(event.transaction.hash.toHexString(), event.logIndex.toString()));
  evt.contract = "SampraanAccessControl";
  evt.eventName = "RoleGranted";
  evt.blockNumber = event.block.number;
  evt.blockTimestamp = event.block.timestamp;
  evt.transactionHash = event.transaction.hash;
  evt.payload = `role=${event.params.role.toHexString()} account=${event.params.account.toHexString()}`;
  evt.save();
}

export function handleRoleRevoked(event: RoleRevoked): void {
  const evt = new BlockchainEvent(eventId(event.transaction.hash.toHexString(), event.logIndex.toString()));
  evt.contract = "SampraanAccessControl";
  evt.eventName = "RoleRevoked";
  evt.blockNumber = event.block.number;
  evt.blockTimestamp = event.block.timestamp;
  evt.transactionHash = event.transaction.hash;
  evt.payload = `role=${event.params.role.toHexString()} account=${event.params.account.toHexString()}`;
  evt.save();
}
