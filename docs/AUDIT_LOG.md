# Audit log

The security service emits an immutable, HMAC-SHA-512-chained audit log of every privileged
operation (DEK wrap/unwrap, KEK lifecycle transitions, mTLS rejections, rate-limit
overflows, admin-list violations). The chain is verifiable end-to-end so tampering with any
historical row is structurally detectable.

## Schema

`security_keys.audit_events` per [`MIGRATIONS.md`](MIGRATIONS.md) V3:

| Column | Type | Notes |
|--------|------|-------|
| `id` | `BIGINT AUTO_INCREMENT` PK | Monotonic. The chain follows id order. |
| `occurred_at` | `DATETIME(6)` | Server clock at write time. |
| `event_type` | `VARCHAR(40)` | One of the values in `AuditEventType` (see catalog below). |
| `actor_subject` | `VARCHAR(255) NULL` | mTLS client cert subject DN, or job name (e.g. `security-service:KekPriorTtlJob`). NULL when identity cannot be established (handshake failures). |
| `dek_handle` | `VARBINARY(16) NULL` | DEK handle if the event references one. |
| `kek_id` | `CHAR(36) NULL` | KEK id if the event references one. |
| `success` | `TINYINT(1)` | True for successful operations and successful failure-handling (e.g. an MTLS_REJECTED with `success=false` is a successful rejection). |
| `detail_json` | `JSON NULL` | Structured detail; MUST NOT contain secret material. |
| `prev_hmac` | `VARBINARY(64)` | HMAC-SHA-512 of the immediately prior row (zero-byte sentinel for `id = 1`). |
| `row_hmac` | `VARBINARY(64)` | HMAC-SHA-512(`AUDIT_HMAC_KEY`, `canonical_payload(row)` ‖ `prev_hmac`). |

## Chain construction

```
row_hmac[n] = HMAC-SHA-512(AUDIT_HMAC_KEY, canonical_payload[n] ‖ prev_hmac[n])
prev_hmac[n] = row_hmac[n − 1]   (zero-byte sentinel for n = 1)
```

`canonical_payload[n]` is the deterministic byte encoding of every column except
`prev_hmac` / `row_hmac` (those are the chain bytes themselves; including them would create
a self-reference). The encoding is **length-prefixed, NOT JSON**:

```
occurred_at_epoch_millis (8 bytes BE)
‖ event_type_len (4 BE) ‖ event_type (UTF-8)
‖ actor_subject_present (1 byte) [‖ len (4 BE) ‖ subject_utf8]
‖ dek_handle_present   (1 byte) [‖ len (4 BE) ‖ handle_bytes]
‖ kek_id_present       (1 byte) [‖ len (4 BE) ‖ kek_id_utf8]
‖ success              (1 byte, 0x00 / 0x01)
‖ detail_present       (1 byte) [‖ len (4 BE) ‖ detail_utf8]
```

JSON whitespace/ordering ambiguity would let two payloads with identical logical content
produce different HMACs and break the chain verifier. Length-prefixed framing avoids that.

Reference: [`AuditChainHasher.kt`](../adapters/outbound/persistence/src/main/kotlin/com/shared/security/adapters/outbound/persistence/audit/AuditChainHasher.kt).

## Writer protocol

`ExposedAuditLogRepository.write(event)` runs inside a single `REPEATABLE_READ` transaction:

1. `SELECT row_hmac FROM audit_events ORDER BY id DESC LIMIT 1 FOR UPDATE`
   — exclusive lock prevents concurrent writers from racing on `prev_hmac`.
2. `prev_hmac := (lock result) ?: INITIAL_PREV_HMAC`
3. `row_hmac := AuditChainHasher.hash(event, prev_hmac)`
4. `INSERT ...`

The row-level lock on the *latest* row is the minimal serialization that still produces a
deterministic chain. Concurrent reads of historical rows are unaffected.

## Verification

`ExposedAuditLogRepository.verifyChain(fromId, toId)` reads the rows in id order and
recomputes each `row_hmac` from `canonical_payload + prev_hmac`. Result:

- `OK` — every recomputed HMAC matches its stored value.
- `EMPTY` — no rows in the requested range.
- `BrokenAt(firstBadId)` — the first row whose `prev_hmac` or `row_hmac` does not match
  the recomputation. **This is structural tamper evidence.**

`AuditLogShipperJob` calls `verifyChain` on every fire before shipping. A broken chain
aborts the ship, emits an `AUDIT_CHAIN_BREAK` audit row, and pages operators (Stream E
wires the alerting path).

## Key management

`AUDIT_HMAC_KEY` is a base64-encoded ≥32-byte secret loaded once at startup by
`AuditHmacKeyProvider.fromEnv()`. It is held in memory only and is **independent of any
KEK** (proposal §10 invariant): a leak of `AUDIT_HMAC_KEY` compromises chain integrity
but does not expose plaintext DEKs, and vice-versa.

## Event-type catalog

All values are constants in
[`AuditEventType`](../application/src/main/kotlin/com/shared/security/application/ports/AuditLogPort.kt).

| Category | Event types |
|----------|-------------|
| **Auth / route gate** (Stream B) | `MTLS_REJECTED`, `RATE_LIMIT_EXCEEDED`, `ADMIN_FORBIDDEN` |
| **DEK operations** (Stream B) | `DEK_GENERATED`, `DEK_WRAPPED`, `DEK_UNWRAPPED`, `DEK_REWRAPPED` |
| **Admin operations** (Stream B + C) | `KEK_ROTATION_REQUESTED`, `KEY_STATUS_VIEWED` |
| **KEK lifecycle** (Stream C — `KekPriorTtlJob`) | `KEK_STAGED`, `KEK_ACTIVATED`, `KEK_QUIESCED`, `KEK_RETIRED` |
| **DEK rotation** (Stream C — `DekRotationJob`) | `DEK_ROTATION_BATCH_OK`, `DEK_ROTATION_BATCH_FAILED` |
| **Health** (Stream C — `KekRotationHealthJob`) | `HEALTH_CHECK_OK`, `HEALTH_CHECK_FAILED` |
| **Audit self-events** (Stream C — shipper) | `AUDIT_CHAIN_VERIFIED`, `AUDIT_CHAIN_BREAK`, `AUDIT_SHIPPED`, `AUDIT_RETENTION_DELETED` |
| **KEK backup** (Stream C — `KekBackupVerifyJob`) | `KEK_BACKUP_VERIFIED`, `KEK_BACKUP_VERIFY_FAILED` |

## Retention

`AuditRetentionJob` (daily, configurable via `SECURITY_AUDIT_RETENTION_INTERVAL_HOURS`)
deletes rows whose `occurred_at < now − retention_duration` **AND** whose `id <=
lastShippedId`. The cold-storage ship gate prevents deletion of rows that have not yet
been mirrored offsite — every retained-then-deleted row exists in immutable cold storage
first.

Default retention: 7 years (FedRAMP AU-11 floor). Configurable via
`SECURITY_AUDIT_RETENTION_DURATION_DAYS` (Stream E env-var addition).

## Cold storage

`AuditLogShipperJob` ships contiguous row ranges to a `ColdStoragePort` implementation.
Stream C ships a [`NoOpColdStorageAdapter`](../infrastructure/src/main/kotlin/com/shared/security/infrastructure/audit/NoOpColdStorageAdapter.kt)
that logs and returns synthetic success — no bytes leave the process. Stream E wires a real
S3/R2 adapter once the vendor is selected.

Receivers can replay the HMAC chain by recomputing each row's `row_hmac` from the canonical
payload + previous row's `row_hmac`. Tampered batches will fail verification on the
receiving side.
