# JWT signing-key lifecycle

State machine + Quartz job catalog for the `jwt_signing_keys` table (Stream K K.0).
Mirrors [`KEK_LIFECYCLE.md`](KEK_LIFECYCLE.md) in shape; the two lifecycles run
independently but follow the same operational discipline.

## 1. State machine

```
                    +---------+
   generate-pair -> | STAGED  |
                    +---------+
                         | activate (SKS-K06)
                         v
                    +---------+
                    | ACTIVE  |    <-- exactly one row at a time (schema invariant)
                    +---------+
                         | another activate
                         v
                    +---------+
                    | PRIOR   |    <-- still in /v1/jwks; consumers may verify
                    +---------+
                         | JwtSigningKeyPriorTtlJob (after PRIOR_TTL_HOURS)
                         v
                    +---------+
                    |QUIESCED |    <-- dropped from /v1/jwks; rejected for verify
                    +---------+
                         | JwtSigningKeyRetentionJob (after QUIESCED_RETENTION_HOURS)
                         v
                    +---------+
                    | RETIRED |    <-- retain_until set; row preserved for audit
                    +---------+
                         | JwtSigningKeyRetentionJob (after retain_until)
                         v
                     (deleted)
```

### 1.1. Singleton-ACTIVE invariant

Enforced at the schema level in [`V5__jwt_signing_keys.sql`](../adapters/outbound/persistence/src/main/resources/security-db/migration/V5__jwt_signing_keys.sql)
via a generated column `active_singleton_marker` (NULL except when status=ACTIVE) +
unique index on it. A concurrent dual-promote is structurally impossible; the second
transaction sees a `DuplicateKeyException` and rolls back. The
`ActivateJwtSigningKeyUseCase` demotes the prior ACTIVE → PRIOR in the same transaction
that promotes the new STAGED → ACTIVE, eliminating any race window.

### 1.2. What "PRIOR" vs "QUIESCED" means

| State | In `/v1/jwks` | Consumer behavior |
|---|---|---|
| ACTIVE | Yes | Used for both signing (security-service) and verifying (consumers). |
| PRIOR | Yes | Used for verifying only. Newly-issued tokens won't carry its kid, but in-flight tokens still verify. |
| QUIESCED | No | Tokens carrying its kid fail verification (`unknown_kid`). The grace window for in-flight tokens has elapsed. |
| RETIRED | No | Same as QUIESCED for the verify path; retained only for audit cross-reference. |

The PRIOR window must be at least as long as the JWT TTL the route layer permits (24 h
cap per [`JWT_OPERATIONS.md`](JWT_OPERATIONS.md) §1.2). The default `PRIOR_TTL_HOURS=24`
satisfies this exactly.

## 2. Quartz jobs

| Job | Cron default | Purpose | Audit event |
|---|---|---|---|
| `JwtSigningKeyHealthJob` | every hour | Sign + verify a fixed payload against the ACTIVE key. Catches a wedged signer (HSM unreachable, KEK rotation broke unwrap, etc.) before consumers notice. | `JWKS_HEALTH_CHECK_FAILED` on any failure path. Success is silent. |
| `JwtSigningKeyPriorTtlJob` | daily 02:00 UTC | Sweeps PRIOR rows whose `activated_at + ttl < now`; transitions them to QUIESCED. | `JWKS_KEY_QUIESCED` per row. |
| `JwtSigningKeyRetentionJob` | daily 02:15 UTC | Sweeps QUIESCED rows whose `quiesced_at + retention_window < now`; transitions them to RETIRED. Then sweeps RETIRED rows whose `retain_until < now`; DELETEs them. | `JWKS_KEY_RETIRED` + `JWKS_KEY_DELETED` per row. |

All three jobs carry `@DisallowConcurrentExecution`. Cron schedules are configurable via
the same env-var pattern used for the KEK jobs (`SECURITY_JWT_SIGNING_*_CRON`).

### 2.1. Defaults — picked deliberately

| Setting | Value | Rationale |
|---|---|---|
| `PRIOR_TTL_HOURS` | 24 h | Matches the route-layer JWT TTL cap; any token in flight must already have expired. |
| `QUIESCED_RETENTION_HOURS` | 24 h | Buys one additional day to investigate a key before it's no longer present in the dashboard's "recent keys" view. |
| `RETIRED_RETENTION_DAYS` | 90 d | Long enough to cover the FedRAMP AU-11 90-day audit-query window without preserving keys indefinitely. |

## 3. Operator actions

Routine operations go through the operator CLI:

```bash
# Mint + activate a fresh keypair (initial bootstrap; HSM ceremony §3)
./security-service jwt-keys generate-pair --activate --operator-email=ops@example.com

# Mint without activating (staging a rotation; see HSM ceremony §4)
./security-service jwt-keys generate-pair --operator-email=ops@example.com

# Promote a previously-staged key to ACTIVE
./security-service jwt-keys activate --kid=<hex> --operator-email=ops@example.com
```

Each CLI invocation writes the corresponding `JWKS_KEY_GENERATED` /
`JWKS_KEY_ACTIVATED` audit row via the same `AuditLogPort` the running server uses.

## 4. Cross-references

* HTTP endpoints + caller-auth model: [`JWT_OPERATIONS.md`](JWT_OPERATIONS.md).
* HSM-anchored ceremony for initial setup, scheduled rotation, emergency replacement, disposal: [`HSM_KEY_CEREMONY.md`](HSM_KEY_CEREMONY.md).
* Cutover plan from monolith HS256 to security-service ES256: [`JWT_CUTOVER.md`](JWT_CUTOVER.md).
* Posture snapshot + FedRAMP crosswalk: [`SECURITY_SCORECARD.md`](SECURITY_SCORECARD.md).
