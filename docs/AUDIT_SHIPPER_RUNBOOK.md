# Audit Log Shipper + KEK Backup Verifier — Runbook (SHIP-01..06, partial)

> Status: SHIP-01 + SHIP-02 + SHIP-05 + SHIP-06 SHIPPED 2026-05-24. SHIP-03 +
> SHIP-04 (real R2/S3 adapters) DEFERRED — operator decides cold-storage vendor
> first.
>
> Source ticket: `meta-project/work-items/phases/phase14/items.md` "Stream C
> follow-up" section.

## Overview

The security service runs three Quartz jobs that need an external "cold
storage" surface:

1. **`AuditLogShipperJob`** — ships immutable audit-log batches to off-host
   storage so the hot `security_keys.audit_events` table can be safely pruned.
2. **`AuditRetentionJob`** — deletes audit rows past the retention floor
   (default 7 years per FedRAMP AU-11), but only rows the shipper has already
   processed.
3. **`KekBackupVerifyJob`** — periodically verifies an offsite backup of the
   wrapped KEK material is readable + decrypts correctly.

As of SHIP-01..02 (2026-05-24) all three jobs are wired into Koin DI +
registered with `SecurityScheduler`, but the **cold-storage and
backup-verifier adapters are `NoOp*` stubs**. The job code paths exercise
end-to-end; only the bytes-leaving-the-process step is missing.

## Current state (as-shipped)

| Component | State | Notes |
|-----------|-------|-------|
| `ColdStoragePort` binding | `NoOpColdStorageAdapter` | logs at WARN, returns `Ok` with a synthetic key |
| `KekBackupVerifierPort` binding | `NoOpKekBackupVerifier` | logs at WARN, returns `Ok` |
| `SecurityScheduler` wiring | wired via Koin; called from `Application.securityModule()` | `.start()` registered; `.stop()` on `ApplicationStopping` |
| `SECURITY_SCHEDULER_ENABLED` | **defaults to `false`** | operator opts in via env var |
| `audit_shipped_checkpoint` table | migration `V6` shipped | single-row tracking last successfully shipped audit row id |
| `RunAuditLogShipperUseCase` wiring | chainVerifier + batchReader + checkpoint provider/saver all wired against `ExposedAuditLogRepository` + `AuditShippedCheckpointRepository` | works end-to-end against the NoOp cold-storage adapter |
| `RunAuditRetentionUseCase` wiring | deleter wired to `ExposedAuditLogRepository.deleteOlderThan(cutoff, maxId)` | retention defaults to 2557 days (7 years) |
| `RunDekRotationUseCase` wiring | wired BUT `activeKekPublicKey` closure returns empty bytes — see "Known gaps" | scheduler-disabled by default so the gap doesn't fire in prod yet |

## Operator decision matrix — when to enable

The scheduler MUST stay disabled (`SECURITY_SCHEDULER_ENABLED=false`) until:

1. **A real `ColdStoragePort` adapter is wired** (SHIP-03). Until then,
   enabling the scheduler runs the audit-log shipper against a NoOp that
   silently drops bytes — but the checkpoint table still advances, which
   means the retention job will eventually delete rows that were never
   actually shipped. **Hard data-loss risk.**
2. **A real `KekBackupVerifierPort` adapter is wired** (SHIP-04). Until
   then, enabling the scheduler runs the verifier against a NoOp that
   always returns `Ok`. The job will emit `KEK_BACKUP_VERIFIED` rows
   regardless of whether a backup actually exists — false-positive signal
   that masks a real failure.
3. **`activeKekPublicKey` closure returns real bytes** (follow-up — needs
   a new method on `CryptoKeyServicePort` that exposes the active KEK's
   raw public-key bytes; today `getPublicKeyFingerprint()` is the only
   key-introspection method on the port). Without this, `DekRotationJob`
   logs a warning and skips work.

## Known gaps — what SHIP-03/04 still need to land

### SHIP-03 — real cold-storage adapter

Build `S3CompatibleColdStorageAdapter` (or whatever vendor-specific name)
against either:

- **Cloudflare R2** (recommended — zero egress fees, S3-compatible API).
  AWS S3 SDK + R2 endpoint URL works out of the box.
- **AWS S3** (familiar; egress fees apply).
- **Backblaze B2** (cheaper egress than S3, S3-compatible).
- **GCP Cloud Storage** (XML API supports S3 compatibility).

The adapter implementation needs:

- env vars: `AUDIT_COLD_STORAGE_ENDPOINT_URL`,
  `AUDIT_COLD_STORAGE_BUCKET`, `AUDIT_COLD_STORAGE_ACCESS_KEY_ID`,
  `AUDIT_COLD_STORAGE_SECRET_ACCESS_KEY`, `AUDIT_COLD_STORAGE_REGION`.
- per-batch object key format: `audit/{yyyy}/{MM}/{dd}/{batchId}.bin`.
- idempotency: `If-None-Match: *` on PUT (S3 conditional write) so a
  retry of the same batch doesn't double-write.
- Encrypt at upload-time with the `BACKUP_KEY` env-var-derived KEK
  (CLAUDE.md note in Shared Key Service §5 — `BACKUP_KEY` is a separate
  32-byte secret, independent of the KEK and `AUDIT_HMAC_KEY`).

### SHIP-04 — real backup verifier

Build `R2KekBackupVerifier` (or vendor equivalent). Logic:

1. List objects in the configured backup bucket; expect a current
   `kek-backup.bin` plus historical `kek-backup-{kek-id}.bin` files.
2. Download the current backup.
3. Decrypt with `BACKUP_KEY`.
4. Verify the decrypted bytes match the in-process wrapped-KEK bytes for
   the currently-active KEK row.
5. Emit `KEK_BACKUP_VERIFIED` on success or `KEK_BACKUP_VERIFY_FAILED`
   on any mismatch / IO error.

### SHIP-follow-up — `CryptoKeyServicePort.getActiveKekPublicKey(): ByteArray?`

Add a new method that returns the raw bytes (or null when no active KEK).
Wire `RunDekRotationUseCase.activeKekPublicKey` to call it. The adapter
(`MlKemCryptoKeyService`) holds them in-process already; surfacing them
through the port is a 5-line change.

## Operational workflow (once SHIP-03/04 land)

### Enabling the scheduler in prod

```bash
# 1. Provision the cold-storage bucket + IAM credentials.
# 2. Set env vars (see SHIP-03 list above).
# 3. Set BACKUP_KEY (32 bytes, base64).
# 4. Flip the scheduler on.
export SECURITY_SCHEDULER_ENABLED=true
# 5. Restart security-app. Confirm via logs:
#    "Starting SecurityScheduler with 6 jobs"
#    "Registered AuditLogShipperJob every N minute(s)"
```

### Cadence tuning

The default cadences come from `SchedulerConfig` env vars:

| Env var | Default | Tuning |
|---------|---------|--------|
| `SECURITY_KEK_HEALTH_INTERVAL_MINUTES` | 60 | hourly probe |
| `SECURITY_KEK_PRIOR_TTL_INTERVAL_MINUTES` | 1440 | daily |
| `SECURITY_DEK_ROTATION_INTERVAL_MINUTES` | 10080 | weekly |
| `SECURITY_AUDIT_SHIP_INTERVAL_MINUTES` | 60 | hourly ship batches |
| `SECURITY_AUDIT_RETENTION_INTERVAL_HOURS` | 24 | daily retention sweep |
| `SECURITY_KEK_BACKUP_VERIFY_INTERVAL_HOURS` | 168 | weekly |

Tighten the audit shipper interval if `audit_events` row growth outpaces
default cadence; loosen if cold-storage egress costs become a concern.

### Monitoring

Operator-facing signals to watch in Grafana (via the existing security-
service Prometheus scrape):

- `audit_shipped_checkpoint.last_shipped_id` should advance monotonically.
  Stall = shipper is failing — check `security_keys.audit_events` for
  `AUDIT_CHAIN_BREAK` rows or shipper exception traces.
- `KEK_BACKUP_VERIFIED` audit-event rate should be ~1/week. Anything
  faster = scheduler config error; anything slower = job is failing.
- `audit_events` row count should remain bounded (retention sweep is
  working) but never zero (shipper is processing + verifying).

### Disaster recovery

If `audit_shipped_checkpoint.last_shipped_id` is stale (shipper has been
down for a week), the retention job is correctly NOT deleting rows the
shipper hasn't seen — the audit table grows but no data is lost. Once the
shipper recovers and catches up, retention resumes.

If a cold-storage batch is suspected lost, the operator can:

1. Read the canonical batch bytes from the source `audit_events` table by
   reconstructing via `ExposedAuditLogRepository.readShipBatch(fromId,
   toId, max)`.
2. Manually re-ship via a one-shot CLI (does not exist today; build if
   the scenario arises).

## File-by-file what changed in this commit batch

| File | Change |
|------|--------|
| `adapters/outbound/persistence/.../audit/V6__audit_shipped_checkpoint.sql` | new Flyway migration |
| `adapters/outbound/persistence/.../audit/AuditShippedCheckpointTable.kt` | Exposed table |
| `adapters/outbound/persistence/.../audit/AuditShippedCheckpointRepository.kt` | load/save repo |
| `adapters/outbound/persistence/.../audit/ExposedAuditLogRepository.kt` | added `readShipBatch` + `deleteOlderThan` |
| `infrastructure/.../di/SecurityServiceModule.kt` | bindings for NoOp ports, 6 use cases, SecurityScheduler |
| `infrastructure/.../Application.kt` | `SecurityScheduler.start()` + `.stop()` lifecycle hooks |
| `docs/AUDIT_SHIPPER_RUNBOOK.md` (this file) | new operator runbook |
| `docs/SECURITY_SCORECARD.md` | chronology entry for SHIP-01/02 + scorecard row stays at C until SHIP-03/04 |
