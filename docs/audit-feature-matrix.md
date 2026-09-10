# SAMPRAAN Functional Audit — Feature Matrix (Phase 1)


SAMPRAAN FEATURE MATRIX (from Phase 1 audit)

| # | Feature | UI | Backend | DB | Contract | Indexer | Tests | E2E working |
|---|---------|----|---------|----|---------|---------|-------|-------------|
| 1 | Authentication | PARTIAL (fake gate: setTimeout->success / OAuth redirect) | YES (OAuth+JWT+session tracking+revocation) | YES (users/sessions) | n/a | n/a | YES | NO local flow — no OAuth IdP; AuthGate fakes it |
| 2 | Identity creation | NO (form missing) | YES identities.create admin-only | YES | YES registerIdentity | via events | YES | NO |
| 3 | Identity listing | YES (list shown, demo fallback) | YES | YES | n/a | n/a | YES | PARTIAL |
| 4 | Identity detail | PARTIAL (single hero card) | YES getIdentityById | YES | YES | n/a | YES | NO |
| 5 | Identity status | NO UI control | YES identities.setStatus | YES | YES setStatus | YES | YES | NO |
| 6 | Identity revocation | NO UI control | YES (setStatus REVOKED) | YES | YES | YES | YES | NO |
| 7 | Role assignment | NO UI at all | NO API (no identityRoles write path!) | YES tables exist | YES grantRole (no backend path) | YES RoleGranted | PARTIAL | NO |
| 8 | Role management | NO | NO | YES | YES | YES | NO | NO |
| 9 | Permission management | NO (static matrix only) | NO API for policies | YES policies table | n/a | n/a | engine unit tests | NO |
| 10 | Policy creation/update | NO | NO API | YES | n/a | n/a | NO | NO |
| 11 | Policy evaluation | YES (EVALUATE button, real) | YES authorizeTransfer | YES | YES | YES | YES | YES (transfer only, hardcoded asset [0]) |
| 12 | Asset creation | YES button (auto-random data, no form) | YES assets.create | YES | YES registerAsset | YES | YES | PARTIAL (no usable form) |
| 13 | NFT minting | implicit via create | YES anchorAsset | tokenId column unused | YES (ERC721 mint) | YES | YES | PARTIAL |
| 14 | Asset metadata | YES display | YES | YES | digests only | n/a | YES | PARTIAL |
| 15 | Asset classification | YES display | YES enum | YES enum | YES digest | n/a | YES | YES |
| 16 | Asset assignment | NO UI | NO API (besu.assignAsset exists, no router) | YES asset_custody | YES assignAsset | YES | NO | NO |
| 17 | Asset transfer | YES (Access page, fixed asset) | YES authorizeTransfer | YES | YES transferCustody | YES | YES | PARTIAL (fixed asset, transfers to ACTOR, not chosen recipient) |
| 18 | Access request | merged into transfer | YES | YES | n/a | n/a | YES | PARTIAL |
| 19 | Access approval/denial | YES decision panel | YES | YES | YES | YES | YES | YES |
| 20 | Audit trail | YES | YES | YES | YES | YES | YES | YES |
| 21 | Blockchain tx detail | PARTIAL (hash in decision proof) | YES blockchain.transaction | YES | YES | YES | YES | NO dedicated view |
| 22 | Security alerts | YES | YES alerts.list | YES | n/a | n/a | NO generation logic | PARTIAL (seeded only) |
| 23 | Security intelligence | YES (advisory) | NO real signal pipeline | YES | n/a | n/a | NO | NO (fake 87 fallback) |
| 24 | Dashboard metrics | YES | YES observatory | YES | n/a | YES | YES | YES (but demo fallbacks) |
| 25 | Admin functions | GenericPage placeholder | PARTIAL | YES | YES | YES | PARTIAL | NO |

GAPS TO CLOSE (implementation plan):
A. AUTH: real local password login (OAuth kept for prod) — users need local auth to demo without external IdP.
B. IDENTITY: create form (DID input/validate), status controls (activate/suspend/revoke), role assignment API+UI, identity history.
C. RBAC: role management API (identityRoles writes) + UI; role-aware UI affordances.
D. POLICY: policy list/inspection API + UI, policy evaluation explainer (why ALLOW/DENY/CHALLENGE).
E. ASSET: real Create Asset form (all schema fields), asset lifecycle controls, assignment workflow API+UI, transfer with recipient selection.
F. TRANSFER: recipient selection, transfer detail with tx evidence, contract-enforced deny (auditor).
G. AUDIT: on-chain vs off-chain distinction, tx detail drawer, real events.
H. BLOCKCHAIN TX: dedicated transaction detail view (hash, block, contract, events).
I. SECURITY INTEL: rule-based signal generation from audit events (denied ops, revoked identity activity) -> security_alerts rows; Intelligence UI shows real signals.
J. DASHBOARD: remove hardcoded fallback numbers; derive from observatory.
K. SEED: deterministic dev seed with 4 roles, several assets, custody, audit history, alerts + LINKED identities (closing documented gap #1) + dev accounts for local login.
L. TESTS: auth (login/invalid/logout/revoked session), RBAC deny matrix, asset create validation, mint failure, transfer matrix, audit evidence, indexer dedup.
M. DEMO: local acceptance tests 1-8 from the task.
