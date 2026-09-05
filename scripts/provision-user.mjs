/**
 * DEMO/LOCAL integration helper: provision a REGULAR platform user linked
 * to a chosen seeded SAMPRAAN identity, and print a valid session token.
 * Usage: node scripts/provision-user.mjs <openId> <did>
 * e.g.:  node scripts/provision-user.mjs sampraan-demo-user did:demo:vikram-singh
 */
import "dotenv/config";
import { randomUUID } from "node:crypto";
import { SignJWT } from "jose";
import mysql from "mysql2/promise";
import process from "node:process";

const url = process.env.DATABASE_URL;
const jwtSecret = process.env.JWT_SECRET;
const appId = process.env.VITE_APP_ID;
const openId = process.argv[2] ?? "sampraan-demo-user";
const did = process.argv[3] ?? "did:demo:vikram-singh";
if (!url || !jwtSecret || !appId) {
  throw new Error("DATABASE_URL, JWT_SECRET and VITE_APP_ID are required (see .env)");
}

const conn = await mysql.createConnection(url);

await conn.execute(
  "INSERT INTO users (openId, name, email, role, loginMethod) VALUES (?, ?, ?, 'user', 'demo') " +
    "ON DUPLICATE KEY UPDATE role='user'",
  [openId, "SAMPRAAN Demo User", "user@sampraan.local"]
);

const [identities] = await conn.execute("SELECT id FROM identities WHERE did = ? LIMIT 1", [did]);
if (identities.length === 0) throw new Error(`No identity found for ${did}. Run pnpm seed:demo first.`);
const identityId = identities[0].id;
await conn.execute(
  "UPDATE identities SET linkedUserId = (SELECT id FROM users WHERE openId = ?) WHERE id = ?",
  [openId, identityId]
);

const key = new TextEncoder().encode(jwtSecret);
const token = await new SignJWT({ openId, appId, name: "SAMPRAAN Demo User" })
  .setProtectedHeader({ alg: "HS256", typ: "JWT" })
  .setIssuedAt()
  .setIssuer(appId)
  .setExpirationTime("7d")
  .sign(key);

await conn.execute(
  "INSERT INTO sessions (id, identityId, sessionId, expiresAt) VALUES (?, ?, ?, ?) " +
    "ON DUPLICATE KEY UPDATE expiresAt = VALUES(expiresAt), revokedAt = NULL",
  [randomUUID(), identityId, token, new Date(Date.now() + 7 * 24 * 3600 * 1000)]
);

console.log(JSON.stringify({ openId, identityId, did, token }, null, 2));
await conn.end();
