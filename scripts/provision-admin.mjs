/**
 * DEMO/LOCAL integration helper: provision a platform admin user, link it to
 * a SAMPRAAN identity, and print a valid session token so live API flows can
 * be exercised without an external OAuth provider.
 *
 * This script is for LOCAL DEMO ONLY — it prints a bearer token to stdout.
 * It is not imported by the application and never runs in production paths.
 */
import "dotenv/config";
import { randomUUID } from "node:crypto";
import { SignJWT } from "jose";
import mysql from "mysql2/promise";
import process from "node:process";

const url = process.env.DATABASE_URL;
const jwtSecret = process.env.JWT_SECRET;
const appId = process.env.VITE_APP_ID;
if (!url || !jwtSecret || !appId) {
  throw new Error("DATABASE_URL, JWT_SECRET and VITE_APP_ID are required (see .env)");
}

const openId = process.env.ADMIN_OPEN_ID ?? "sampraan-demo-admin";
const conn = await mysql.createConnection(url);

// Upsert platform admin user
await conn.execute(
  "INSERT INTO users (openId, name, email, role, loginMethod) VALUES (?, ?, ?, 'admin', 'demo') " +
    "ON DUPLICATE KEY UPDATE role='admin'",
  [openId, "SAMPRAAN Demo Admin", "admin@sampraan.local"]
);

// Ensure a linked SAMPRAAN identity (reuse the seeded Aarav Mehta ADMIN identity)
const [identities] = await conn.execute(
  "SELECT id FROM identities WHERE did = ? LIMIT 1",
  ["did:demo:aarav-mehta"]
);
if (identities.length === 0) throw new Error("Run pnpm seed:demo first — no demo identity found");
const identityId = identities[0].id;
await conn.execute(
  "UPDATE identities SET linkedUserId = (SELECT id FROM users WHERE openId = ?) WHERE id = ?",
  [openId, identityId]
);

// Mint the session token exactly like sdk.createSessionToken does.
const key = new TextEncoder().encode(jwtSecret);
const token = await new SignJWT({ openId, appId, name: "SAMPRAAN Demo Admin" })
  .setProtectedHeader({ alg: "HS256", typ: "JWT" })
  .setIssuedAt()
  .setIssuer(appId)
  .setExpirationTime("7d")
  .sign(key);

// Track the issued platform session so server-side revocation has a row to
// revoke (sessions.sessionId mirrors the issued token).
await conn.execute(
  "INSERT INTO sessions (id, identityId, sessionId, expiresAt) VALUES (?, ?, ?, ?) " +
    "ON DUPLICATE KEY UPDATE expiresAt = VALUES(expiresAt), revokedAt = NULL",
  [randomUUID(), identityId, token, new Date(Date.now() + 7 * 24 * 3600 * 1000)]
);

console.log(JSON.stringify({ openId, identityId, token }, null, 2));
await conn.end();
