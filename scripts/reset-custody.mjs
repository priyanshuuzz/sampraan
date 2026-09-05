/**
 * One-shot demo helper: move ASSET-LIVE-EVIDENCE-001 custody on-chain from
 * the admin's derived wallet to Ananya Rao's derived wallet, so the UI can
 * then perform a REAL transfer back. Not part of the server runtime.
 */
import { ethers } from "ethers";
import fs from "node:fs";

const RPC = "http://localhost:8545";
const OPERATOR_KEY_RAW =
  "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63";
const ASSET_ID = "ASSET-LIVE-EVIDENCE-001";
const TOKEN_ID = 15;
const FROM_DID = "did:demo:aarav-mehta"; // current custodian (admin)
const TO_DID = "did:demo:ananya-rao";

const cfg = JSON.parse(fs.readFileSync("blockchain/deployment.json", "utf8"));
const provider = new ethers.JsonRpcProvider(RPC);
const wallet = new ethers.Wallet(OPERATOR_KEY_RAW, provider);

const assetAbi = JSON.parse(
  fs.readFileSync("blockchain/artifacts/SampraanAssetRegistry.json", "utf8")
).abi;
const idAbi = JSON.parse(
  fs.readFileSync("blockchain/artifacts/SampraanIdentityRegistry.json", "utf8")
).abi;

const asset = new ethers.Contract(cfg.contracts.SampraanAssetRegistry, assetAbi, wallet);
const idReg = new ethers.Contract(cfg.contracts.SampraanIdentityRegistry, idAbi, wallet);

const operatorKey = ethers.keccak256(ethers.toUtf8Bytes(OPERATOR_KEY_RAW));
function derivedWallet(did) {
  const seed = ethers.keccak256(
    ethers.solidityPacked(["bytes32", "string"], [operatorKey, did])
  );
  return new ethers.Wallet(seed).address;
}

const adminW = derivedWallet(FROM_DID);
const ananyaW = derivedWallet(TO_DID);
console.log("admin derived wallet:", adminW);
console.log("ananya derived wallet:", ananyaW);

const st = await idReg.getIdentity(ananyaW);
console.log("ananya on-chain status:", st.status.toString());
if (!(await idReg.isActive(ananyaW))) {
  console.log("Ananya not anchored — registering wallet on-chain first...");
  const didDigest = ethers.keccak256(ethers.toUtf8Bytes(TO_DID));
  const keyDigest = ethers.keccak256(ethers.toUtf8Bytes("derived:" + TO_DID));
  const regTx = await idReg.registerIdentity(ananyaW, didDigest, keyDigest);
  const regRc = await regTx.wait();
  console.log("anchor tx:", regRc.hash, "block", regRc.blockNumber);
}
console.log("ananya on-chain active:", await idReg.isActive(ananyaW));

const cur = await asset.custodianOf(TOKEN_ID);
console.log("current on-chain custodian:", cur);
console.log("current asset status:", (await asset.assetStatus(TOKEN_ID)).toString());

if (cur.toLowerCase() === ananyaW.toLowerCase()) {
  console.log("Custody already with Ananya — nothing to do.");
  process.exit(0);
}

const tx = await asset.transferCustody(TOKEN_ID, ananyaW);
const rc = await tx.wait();
console.log("reset tx:", rc.hash, "block", rc.blockNumber, "status", rc.status);

console.log("custodian after reset:", await asset.custodianOf(TOKEN_ID));
console.log("DONE");
