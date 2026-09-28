# SAMPRAAN Controlled Asset Content Architecture

This document describes the REAL digital-asset content system: encrypted
content storage, versioning, integrity verification, and the authorization
model that gates every operation. Companion to `docs/did-architecture.md`.

## 1. From registry record to controlled digital asset

An `assets` row remains the registered, NFT-backed registry record. Its
ACTUAL digital content lives in versioned, encrypted content objects:

```
Application (tRPC, session-authenticated)
    ↓ every operation authorizes server-side (evaluateContentAccess)
Asset Content Service (server/modules/asset-content)
    ↓ AES-256-GCM envelope encryption (per-object DEK)
StorageProvider abstraction (storage.ts)
    ↓ ciphertext only
LocalEncryptedStorageProvider (dev)  |  IpfsStorageProvider (Kubo API)
```

Security invariants:

- Plaintext never persists — not in the DB, not in the storage backend, not
  in logs. Only ciphertext reaches a provider.
- Only wrapped (envelope-encrypted) key material is stored in the DB.
- No raw storage paths or provider URLs are ever exposed to clients.
- **There is no download endpoint, no public file URL, and no permanent
  signed URL — by design.** Content reaches an authorized browser only
  through the authenticated `content.view` channel after server-side
  authorization, rendered inside the asset workspace.
- The CID / storage reference is NOT an authorization boundary: possession
  of a reference grants nothing (it is ciphertext, and reads still pass the
  authorization layer).

## 2. Data model

| Table | Purpose |
| --- | --- |
| `asset_content_versions` | One row per version: version number (gapless, `(assetId, versionNumber)` UNIQUE), sanitized filename, server-sniffed MIME, plaintext size, **plaintext sha256**, storage provider + reference, encryption envelope (alg, keyId, wrapped DEK, iv, tag), creator identity, change note, chain anchor fields. |
| `asset_access_grants` | Explicit VIEW/EDIT grants extending access beyond owner/custodian; soft-revocable (revoked rows stay for audit); re-issuing a previously revoked (asset, grantee, permission) triple atomically REVIVES the soft-revoked row — the UNIQUE constraint spans live and revoked rows and is what keeps racing grants safe, so no second row is created. |

The asset row itself keeps `integrityHash` (registry-level digest) and
`tokenId` (on-chain NFT). Content hashes live per-version.

## 3. Encryption

- **AES-256-GCM (authenticated encryption)** with a fresh 256-bit DEK per
  object; the DEK is wrapped with the master key and stored alongside
  (iv, ciphertext, tag) references in the DB row.
- Any ciphertext tamper fails GCM authentication at decryption —
  integrity verification never claims success on modified content.
- The content reference is an HMAC-derived, content-addressed string
  (CIDv1-shaped) of `HMAC(integrityKey, ciphertext ‖ plaintextHash)` —
  dedup-friendly, tamper-evident, and not computable from public data.

Key custody (honest scope): the master key comes from server-side
configuration (`ASSET_CONTENT_MASTER_KEY` hex; dev fallback derives from the
deployment secret and refuses to boot in production without the explicit
variable). This is **not** an HSM/KMS. The `AssetKeyProvider` interface
(`wrapKey` / `unwrapKey` / `integrityKey`) is the seam for a production
KMS/HSM — the domain code never handles raw master key material directly.

## 4. Upload pipeline (server-enforced, in order)

1. Authenticate (session) and authorize EDIT/UPLOAD via the content gate.
2. Size validation (20 MiB default, `ASSET_CONTENT_MAX_BYTES`).
3. **MIME sniffing from magic bytes / structure** — the client's
   Content-Type is ignored. Allowlist: PDF, PNG, JPEG, plain text, CSV,
   JSON, Markdown, XML, HTML. Binary garbage renamed `.txt` is rejected
   (NUL/control-byte and UTF-8 structural checks).
4. Filename sanitization (traversal-neutralized, control-stripped,
   length-bounded; the original name is kept for attribution only).
5. sha256 of the plaintext computed server-side.
6. Encrypt (envelope), store ciphertext via the provider.
7. Version row inserted with an atomically allocated version number
   (`(assetId, versionNumber)` UNIQUE makes concurrent creation safe).
8. Audit evidence (`ASSET_VERSION_CREATED`, or explicit failure events —
   including `ASSET_VERSION_PERSIST_FAILED` if the DB row fails after the
   object was stored, so orphans are visible).
9. Chain provenance is best-effort; the version's hash is recorded in the
   audit event (see §7).

## 5. Versioning

Versions are append-only. A new upload creates vN+1 with its own ciphertext,
hash, and reference; historical versions are never overwritten or deleted by
the product flows. Every version is attributable to an identity, timestamp,
content hash, and storage reference, and appears in the workspace version
table (current marked). Integrity verification works per version, including
historical ones.

## 6. Integrity verification

`content.verifyIntegrity` retrieves the stored ciphertext through the
storage abstraction, decrypts (GCM-authenticated), recomputes sha256 of the
plaintext, and compares against the recorded hash + size. Result states:

- `INTEGRITY_VERIFIED` — recomputed hash matches the record.
- `INTEGRITY_MISMATCH` — recorded vs computed differ (or size drifted);
  surfaced as a denial-class audit event and an advisory intelligence signal.
- `CONTENT_UNAVAILABLE` — the provider cannot serve the object.
- `VERIFICATION_ERROR` — decryption/key failure (e.g. tamper).

The audit event records the state; the UI renders the verdict verbatim.
Verification is never asserted by the client or faked server-side.

## 7. Storage abstraction and IPFS

`StorageProvider` port: `put` / `get` / `stat` / `delete` / `stream` over
opaque encrypted blobs addressed by content reference.

- `LocalEncryptedStorageProvider` — deterministic dev store OUTSIDE the
  repository (`LOCALAPPDATA` / `XDG_DATA_HOME` / `~/Library`; configurable
  via `ASSET_CONTENT_STORAGE_DIR`), sharded layout, traversal-safe
  reference validation, write-then-rename persistence. Uploads can never
  enter git.
- `IpfsStorageProvider` — Kubo HTTP API adapter (`/api/v0/add?pin=true`,
  `/api/v0/cat`). The CID of the ENCRYPTED blob is the storage reference.
  Selection: set `IPFS_API_URL` to switch providers via configuration; no
  domain code changes.

Deliberate rules: no public gateway is used for reads (only the configured
node); the CID alone is never an access path; plaintext is never placed on
IPFS or any provider; files are never stored on-chain (the chain holds only
digests).

## 8. Authorization model

`evaluateContentAccess` (server-side, per asset + per operation) resolves
every security input from the session and the database:

- identity status (ACTIVE required), asset status (REVOKED blocks all);
- role + permission (`asset:read` for VIEW, `asset:edit` for EDIT/UPLOAD,
  `asset:assign` for MANAGE_ACCESS; `administration:manage` or platform
  admin covers the catalog);
- ownership/custody baseline (owner and custodian can VIEW; EDIT needs
  owner/custodian/admin or an EDIT grant);
- explicit access grants (`asset_access_grants`) extend VIEW/EDIT;
- classification restrictions: SENSITIVE-and-above content requires an
  explicit relationship (owner/custodian/admin/grant) — a bare
  `asset:read` holder cannot read it;
- step-up: SENSITIVE-and-above VIEW and every EDIT/UPLOAD require a
  server-verified step-up bound to the exact purpose
  (`content-view:<assetId>` / `content-edit:<assetId>`).

Every decision — including denials and challenges — is persisted as audit
evidence with actor attribution, INCLUDING the post-authorization view and
integrity-verdict events (`ASSET_CONTENT_VIEWED`, `ASSET_INTEGRITY_*`),
which are attributed to the identity the gate resolved. Asset APIs accept
only asset/version identifiers from the browser; actor identity, role,
ownership, grant, and step-up state are always derived server-side
(verified by spoofing tests).

## 9. Workspace UX

The asset detail panel hosts the controlled workspace (`AssetWorkspace`):
current version summary (file, MIME, size, sha256, storage provider),
version history with per-version view/verify, controlled in-workspace
viewer (text formats rendered; binary formats show metadata + integrity
with no invented editing), new-version upload, and integrity verdicts.
Actions are permission-aware; every control reflects a server decision and
the backend re-authorizes on every call.

## 10. Role matrix (content operations)

| Role | VIEW | EDIT / new version | MANAGE ACCESS |
| --- | --- | --- | --- |
| ADMIN | yes | yes | yes |
| MANAGER | yes (with `asset:edit` for mutations; custodian or granted) | yes where policy permits | no |
| AUDITOR | metadata + permitted content (read-only envelope) | **no** | no |
| USER | only explicitly granted/custodian assets | no | no |

Existing transfer/assignment/approval semantics are unchanged and remain
the source of truth for custody operations.

## 11. Demo data

The dev seed stores FICTIONAL content through the real pipeline:
`System_Configuration.txt`, `Equipment_Inspection_Report.txt`,
`Firmware_Release_Notes.txt` — encrypted at rest, integrity-verifiable,
clearly marked as fictional development data.

## 12. Known limitations (honest disclosure)

- Key custody is server-side configuration, not HSM/KMS (interface seam
  exists; see §3).
- Streaming is decrypt-then-stream: the full ciphertext is buffered for GCM
  authentication before delivery, bounded by the upload limit ×4 — fine for
  the 20 MiB class of documents, not for multi-GB artifacts.
- The deployed `SampraanAssetRegistry` has no version-reference method; the
  version's content hash is evidenced in the application audit trail, and
  version anchoring is recorded honestly as SKIPPED until a version-aware
  contract upgrade.
- IPFS integration targets the Kubo HTTP API; pinning services and
  gateway-based retrieval are intentionally not used for confidentiality
  reasons.
