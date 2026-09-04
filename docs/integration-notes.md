# Integration Notes: Operational Gaps (Known and Accepted)

These gaps were identified during the integration of the five feature
branches (979e445 backend, 2b2712a security, 283d7dd blockchain, 3087846
testing, bc96108 frontend) into `integration/sampraan-final`. Each one is
documented rather than silently worked around: none of them weakens a
security property, and each has a safe default.

## 1. identities.linkedUserId is not populated by the demo seed

**What.** The authorization boundary resolves the acting identity with
`getIdentityByLinkedUserId(ctx.user.id)` — the SAMPRAAN identity linked to
the authenticated platform user. The seed script (`seed-demo.mjs`) does
not populate `identities.linkedUserId`, so a freshly seeded database has
identities on record but none linked to any platform user.

**Effect.** Until an operator links a seeded identity to a user (or a
linked identity is created), every `assets.authorizeTransfer` request
evaluates the actor as `UNREGISTERED` and the engine DENIES. The audit
event is still recorded (with a nullable actor identity id).

**Why this is the correct default.** The alternative — fabricating a
linkedUserId in the seed, or falling back to the asset owner identity —
would attribute transfer authority to an identity the platform never
verified, which is precisely the misattribution the security hardening
removed (decisions are attributed to the ACTING identity, never the
resource owner). Fail-closed here is the documented SAMPRAAN posture:
**no linked identity → DENY, never a guess.**

**How to close it operationally.** Link a seeded identity to the platform
user before running transfer scenarios:

```sql
UPDATE identities SET linkedUserId = <users.id> WHERE did = '<did>';
```

`DATABASE_URL` is unset in this environment, so the DB path is exercised
through the unit tests with the db layer mocked (`routers.security.test.ts`,
`routers.test.ts`); the live database flow needs a configured MySQL
instance.

## 2. No server-verified step-up mechanism exists

The engine exposes `context.stepUpAuthenticated` for a future
server-verified step-up flow, but no such mechanism is implemented
anywhere in the stack. The tRPC boundary therefore never passes a
`context` object into `evaluate`: a HIGHLY_SENSITIVE transfer yields
**CHALLENGE** (POLICY-STEP-UP) for every role — including ADMIN — because
client-asserted step-up must never be trusted. This is intentional; do not
"fix" it by forwarding a client flag.

## 3. authorization_decisions.policyId is stored as null for inline policy labels

The engine returns inline policy labels (`POLICY-HIGH-SENS-TRANSFER`,
`POLICY-STEP-UP`), but `authorization_decisions.policyId` is FK-bound to
`policies.id` (UUID varchar(36)). The labels are not UUIDs, so the
decision row stores `policyId: null` and the label is recorded in the
audit event metadata instead. This preserves referential integrity; no
policy table rows were fabricated.

## 4. Live OAuth E2E is unavailable in this environment

OAuth sign-in requires external credentials (`OAUTH_SERVER_URL`) that are
not configured. The session/verification layer is covered by
`sdk.session.test.ts` and `sdk.test.ts` (signing, appId binding, foreign
secret, tamper, expiry, garbage input). The live path is documented as
unverified rather than mocked green.
