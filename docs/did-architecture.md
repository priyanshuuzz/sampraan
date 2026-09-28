# SAMPRAAN DID Architecture — Cryptographic Identity Lifecycle

This document describes the hardened DID (decentralized identifier)
subsystem: what is implemented today, what it guarantees, and what remains a
production-hardening task. It is written to be auditable: every security
claim below maps to a test in the repository.

## 1. What the DID is in SAMPRAAN

SAMPRAAN identities are directory records (`identities`) that carry roles and
permissions (RBAC). Each identity owns exactly one DID (`did_records`), and
the DID is the cryptographic control plane:

```
platform session (JWT + server-side tracking)
      │  resolves, on EVERY request
      ▼
linked SAMPRAAN identity  ──▶  DID  ──▶  verification key (generation N)
      │                                       │
      │                                       │ challenge-response proves
      ▼                                       ▼ control at login / step-up
roles + permissions (RBAC)            signature verified server-side
      ▼
ABAC policy engine (classification, custody, grants, step-up, approvals)
      ▼
operation + audit evidence
```

Separation of responsibilities (never mixed):

- **DID proves WHO** — possession of the current verification key.
- **RBAC decides WHAT** — role → permission → action.
- **ABAC adds CONTEXT** — classification, ownership/custody, grants,
  step-up state, approval state, asset status.
- **Real-world identity** is established by the organization's enrollment
  process (admin creates the identity and links it to a person). Neither the
  DID nor the blockchain proves a human's identity; they prove control of a
  cryptographic credential and anchor state transitions.

## 2. Data model

| Table | Purpose |
| --- | --- |
| `identities` | Directory profile + lifecycle (`ACTIVE` / `SUSPENDED` / `REVOKED`), linked platform user. |
| `did_records` | One DID per identity. DID status (`ACTIVE`/`REVOKED`), key status (`ACTIVE`/`ROTATED`/`REVOKED`), current `keyIdentifier`, `rotatedFrom`, timestamps, public DID document JSON. |
| `did_key_records` | Per-generation key history: key id, algorithm, status, superseded-by, deactivated-at. Evidence-grade; nothing is destroyed on rotation. |
| `did_challenges` | Single-use structured challenges (see §4): did, purpose, audience, keyIdentifier, nonce, canonical message, expiry, consumption marker. |
| `step_up_sessions` | Purpose-bound step-up markers consumed atomically at verification. |
| `public_keys` | Legacy public-key registry (algorithm, key identifier, status) — retained for the existing DID lifecycle screens. |

Key identifiers are digests (`key-<generation>-<hash12>`), never secret
material. **No private key is ever stored in any table.**

## 3. Keys and the key provider seam

Current implementation (honest scope):

- Signature scheme: **ECDSA secp256k1 with EIP-191 personal-message
  recovery** (`EcdsaSecp256k1RecoveryMethod2020`), via `ethers` — the same
  primitive the Besu layer already trusts.
- The dev provider (`LocalDevDidKeyProvider`,
  `server/modules/did/did-key-provider.ts`) derives each DID's signing seed
  deterministically from the operator key + DID string, matching
  `deriveIdentityWallet()` used for on-chain anchoring. The server only ever
  needs the derived ADDRESS to verify; it does not ship or persist keys.
- This is a development provider. It is **not** an HSM and must not be
  represented as one.

Production seam (implemented as an interface, not yet backed by a KMS):

```
DidKeyProvider {
  sign(context, message)          // KMS: Sign API inside the boundary
  expectedAddress(context)        // KMS: public key metadata
}
```

A KMS/HSM implementation (AWS KMS, Azure Key Vault, Vault Transit, CloudHSM)
replaces the provider by configuration; authentication code is unchanged.
Until that provider exists, the master derivation key is server-side
configuration (`BLOCKCHAIN_PRIVATE_KEY` in the dev chain) and rotation means
generation bumping of key identifiers with server-side verification — not
hardware key custody. **Do not deploy this as-is where key custody must be
hardware-backed.**

## 4. Challenge-response (structured, domain-separated)

`did.requestChallenge` issues a challenge whose signed payload is canonical
and structured — the server never verifies arbitrary strings:

```
SAMPRAAN DID Authentication
version: 2
did: did:sampraan:operator-42
keyId: key-3-a1b2c3d4e5f6
purpose: AUTHENTICATION
audience: sampraan-local
nonce: <192-bit CSPRNG hex>
issued-at: 2026-09-27T09:00:00.000Z
expires: 2026-09-27T09:05:00.000Z
Signing this message proves control of this DID key for the stated purpose only.
...
```

Bindings and why they matter:

| Field | Defeats |
| --- | --- |
| `did` | challenge substitution between identities |
| `keyId` | a signature from generation N authenticating as N+1 (rotation kills in-flight challenges) |
| `purpose` | cross-purpose replay (AUTHENTICATION proof ≠ STEP_UP proof) |
| `audience` (appId) | replaying a challenge captured for another deployment |
| `nonce` (192-bit) | precomputation / collision |
| `iat` / `expires` | long-lived challenge windows (TTL 5 min, enforced from the DB row, not the signed clock) |
| `version` | format downgrade / stale-payload acceptance |

Client input never includes any of these values except the DID itself; the
server issues everything else and stores the canonical message.

## 5. Replay protection

`did.verifyChallenge` consumes the challenge with a single guarded UPDATE:

```sql
UPDATE did_challenges SET consumedAt = now()
WHERE nonce = ? AND did = ? AND purpose = ?
  AND consumedAt IS NULL AND expiresAt > now();
```

- `affectedRows = 0` ⇒ reject (`CHALLENGE_INVALID`). Under concurrency
  exactly one request can flip the row — verified by a test that fires 8
  parallel verifications and asserts exactly 1 success.
- Consumption happens BEFORE signature checks, so even a valid signature
  cannot resurrect a consumed or expired challenge.
- Purpose is part of both the WHERE clause and the signed payload, so
  cross-purpose replay fails twice over.

## 6. Key lifecycle

**Rotation** (`did.rotateKey`, self-service or admin — IDOR-hardened):

1. Old generation marked `ROTATED` in `did_key_records` (superseded-by set).
2. New generation `key-<n+1>-<digest>` becomes the DID's `keyIdentifier`,
   status `ACTIVE`, `rotatedFrom` links the chain.
3. Outstanding challenges bound to the old keyId fail verification
   (`KEY_SUPERSEDED` / `CHALLENGE_INVALID`).
4. History is preserved: past audit events remain attributable to the key
   generation that produced them. Nothing is deleted.

**Revocation** (`did.setKeyStatus`, admin-only): the current generation is
marked `REVOKED` on both the DID row and the key history; challenge issuance
fails immediately (`KEY_REVOKED`), and a challenge issued before revocation
fails at verification (lifecycle is re-read at verification time, not issue
time). Re-activation is an explicit admin action, also audited.

**DID revocation** (existing identity lifecycle, `identities.setStatus`):
a `REVOKED`/`SUSPENDED` identity fails the session gate on its very next
request (`sdk.authenticateRequest`), step-up issuance fails, all protected
operations deny, and the DID document's lifecycle metadata reflects it.

## 7. Step-up authentication

Step-up reuses the identical machinery with `purpose` set to the specific
operation. Purposes are composed by a SINGLE server-side source of truth
(`stepUpPurposeFor`): `content-transfer:<asset row id>` for custody
transfers, `content-view:<asset row id>` / `content-edit:<asset row id>`
for content operations — the challenge issuer and every authorization gate
probe the exact same token, and the asset ROW id (not the business key) is
the bound resource identity:

- bound to identity + purpose + audience + keyId + single-use nonce;
- TTL 5 minutes; verified marker valid 10 minutes after consumption;
- cross-purpose replay rejected (test: a `transfer:asset-1` proof cannot
  authorize `content-edit:asset-2`, and `hasValidStepUp` is purpose-scoped);
- authorization gates re-check `hasValidStepUp(identityId, purpose)` with
  the SERVER-computed purpose string on every sensitive operation — the
  client cannot assert step-up state (verified by spoofing tests).

## 8. DID Document

`did.document` resolves a public-safe document:

```json
{
  "id": "did:sampraan:operator-42",
  "verificationMethod": [{
    "id": "did:sampraan:operator-42#key-3-a1b2c3d4e5f6",
    "type": "EcdsaSecp256k1RecoveryMethod2020",
    "controller": "did:sampraan:operator-42",
    "blockchainAccountId": "eip155:4224:0x…"
  }],
  "authentication": ["did:sampraan:operator-42#key-3-…"],
  "assertionMethod": ["did:sampraan:operator-42#key-3-…"],
  "sampraan": {
    "status": "ACTIVE", "keyStatus": "ACTIVE",
    "keyIdentifier": "key-3-…", "rotatedFrom": "key-2-…",
    "identityStatus": "ACTIVE",
    "keyHistory": [{ "keyIdentifier": "…", "status": "ROTATED", … }]
  }
}
```

- No private key material can appear (test asserts the serialization never
  contains key material).
- The method string is the internal prototype method. This is **not** a
  claim of universal DID-method interoperability; resolution is a SAMPRAAN
  read model, not a public DID registry.

## 9. Blockchain identity anchoring

Unchanged from the existing architecture and fully compatible with the
hardening: each DID maps to a deterministic on-chain reference wallet
(derived, not stored); the chain anchors only keccak256 digests (DID digest,
public-key digest) and lifecycle status. Private keys never touch chain
state. The chain re-verifies identity status for protected transitions
independently of the backend decision.

## 10. Audit evidence

Identity lifecycle events recorded in `audit_events` (actor attributed from
the session; nonces only ever logged as fingerprints):

`DID_CHALLENGE_REQUESTED` (with purpose + keyId + nonce fingerprint),
`DID_AUTH_SUCCEEDED` / `DID_AUTH_FAILED` (with reason code),
`DID_KEY_ROTATED` (from → to generation),
`DID_KEY_REVOKED` / `DID_KEY_ACTIVATED`,
`DID_DOCUMENT_RESOLVED`,
`STEP_UP_CHALLENGE_ISSUED` / `STEP_UP_SUCCEEDED` / `STEP_UP_FAILED`,
`IDENTITY_CREATED` / `IDENTITY_SUSPENDED` / `IDENTITY_REVOKED` /
`IDENTITY_REACTIVATED`,
`AUTHORIZATION_DENIED` / `AUTHORIZATION_CHALLENGED` for every denied
protected operation.

Never logged: private keys, raw nonces, session tokens, signatures.

## 11. Test matrix (what is actually proven)

`server/modules/did/did-hardening.test.ts` (DB-backed, 21 tests) and
`server/did.router.security.test.ts` (router boundary, 8 tests) cover:

1. valid authentication; 2. unknown DID; 3. revoked DID/key; 4–5. wrong key,
   invalid signature; 6. modified payload; 7. DID substitution; 8. expired
   challenge; 9. replay; 10. concurrent replay (8-way race → exactly 1
   success); 11. rotation mints generations + preserves history; 12.
   pre-rotation challenge dies post-rotation; 13. new key works after
   rotation; 14. revocation blocks issuance AND verification; 15. repeated
   rotation converges to exactly one ACTIVE generation; 16. concurrent
   rotation keeps the DID usable; 17. key-id derivation is
   generation-scoped; 18. DID document resolves without private material;
19–21. step-up purpose binding, cross-purpose replay, purpose-scoped
validity. Router tests add: client-asserted identity/role/DID/owner fields
are ignored; revoked identity denied asset + content operations; step-up
assertions ignored (server-computed purpose); session identity mismatch.

## 12. Implemented vs planned

**Implemented and tested:** everything in §2–§11 above.

**Planned production hardening (not implemented — do not assume):**

- KMS/HSM-backed `DidKeyProvider` (key generation and signing inside the
  hardware boundary; per-key metadata instead of deterministic derivation).
- A public/standards-compliant DID method + universal resolver integration.
- Device-bound session binding (step-up is currently identity+purpose
  bound; a stolen unlocked session within the validity window is still a
  risk window of ≤10 minutes for the exact purpose).
- Formal third-party security audit.
