# KEK lifecycle

Every ML-KEM-768 keypair the security service has known about is represented as one row in
the `keks` table (see [`MIGRATIONS.md`](MIGRATIONS.md)) progressing through a four-state
machine. The state machine and rotation sequence are defined by proposal §8.

```
                   ┌─────────┐
   admin route ──▶ │ STAGED  │
                   └────┬────┘
                        │ (activation)
                        ▼
                   ┌─────────┐
                   │ ACTIVE  │ ◀── at most one row, schema-enforced
                   └────┬────┘
                        │ (rotation begins → new STAGED becomes ACTIVE)
                        ▼
                   ┌─────────┐
                   │ PRIOR   │ ◀── tolerated on unwrap during quiesce window
                   └────┬────┘
                        │ (DekRotationJob rewraps all remaining DEKs;
                        │  KekPriorTtlJob retires once quiesce TTL elapsed
                        │  AND no DEK still references this kek_id)
                        ▼
                   ┌─────────┐
                   │ RETIRED │ ◀── audit anchor only; no DEK still references this row
                   └─────────┘
```

## STAGED → ACTIVE

`POST /v1/admin/rotate-kek` produces fresh keypair material via
`CryptoKeyServicePort.generateNewKekPair()`. The route returns the new keypair to the
operator; the operator (or a Stream-E follow-on) writes a `STAGED` row to `keks` and
installs the new private key under the file-mount secret store. Activation is the explicit
operator step that flips `status = 'ACTIVE'` and demotes the current ACTIVE row to PRIOR.

**Singleton-ACTIVE invariant:** schema-enforced via a generated column + unique index
(see `V1__keks.sql`). A second concurrent activation fails.

## ACTIVE → PRIOR

Demoted automatically when a new KEK is activated. The row's `quiesced_at` is set to the
demotion timestamp; the TTL countdown for retirement starts from there.

## PRIOR → RETIRED

`KekPriorTtlJob` evaluates each PRIOR row hourly:

```
candidates = SELECT * FROM keks WHERE status = 'PRIOR'
for each candidate:
    if (now − candidate.quiesced_at) < quiesceWindow → blockedByTtl++
    else if (count of deks WHERE kek_id = candidate.id) > 0 → blockedByDeks++
    else → retire(candidate)  -- transitions to RETIRED, emits KEK_RETIRED audit
```

Two structural guards apply simultaneously:

1. **TTL guard:** quiesce window has elapsed (default `SECURITY_KEK_QUIESCE_WINDOW_HOURS = 24`).
2. **Reference guard:** no `deks` row still has `kek_id` pointing at this KEK.

The reference guard is the load-bearing one — a KEK is structurally still in use as long as
even one DEK references it. The TTL guard is a minimum, not a maximum; in practice the KEK
only retires once `DekRotationJob` has rewrapped every DEK to the active KEK.

Reference:
[`RunKekPriorTtlUseCase.kt`](../application/src/main/kotlin/com/shared/security/application/usecases/RunKekPriorTtlUseCase.kt).

## DEK rotation under a PRIOR KEK

`DekRotationJob` runs at configurable interval (default
`SECURITY_DEK_ROTATION_INTERVAL_MINUTES = 10_080`, i.e. weekly). Each fire:

1. Looks up the active KEK and the PRIOR KEKs.
2. For each PRIOR KEK, reads up to `SECURITY_DEK_ROTATION_BATCH_SIZE` DEKs still bound to it.
3. For each DEK in the batch: `crypto.rewrapDekForNewKek(existing, newPublicKey)` → write
   new wrapped bytes + reassign `kek_id` to the active KEK.
4. Emits `DEK_ROTATION_BATCH_OK` audit with the rewrapped count.

Batch sizing keeps individual transactions short (avoids long row locks under load). A
fire that rewraps `batchSize` DEKs stops there; the next fire continues from the oldest
remaining DEK on a PRIOR KEK.

Reference:
[`RunDekRotationUseCase.kt`](../application/src/main/kotlin/com/shared/security/application/usecases/RunDekRotationUseCase.kt).

## Health probing

`KekRotationHealthJob` runs hourly (configurable via
`SECURITY_KEK_HEALTH_INTERVAL_MINUTES`) and exercises the full wrap → unwrap path against
the active KEK using a fresh probe DEK:

1. `crypto.generateDek()` produces a new wrapped+plaintext DEK pair.
2. `crypto.unwrapDek(wrapped)` recovers the plaintext.
3. Plaintext bytes are zeroized.
4. On success → `HEALTH_CHECK_OK` audit row.
5. On exception → `HEALTH_CHECK_FAILED` audit row with the exception class name.

A failed probe is the strongest early signal of corruption in the active KEK's in-memory
material or in the BC ML-KEM library's behaviour after a JVM update.

Reference:
[`RunKekHealthCheckUseCase.kt`](../application/src/main/kotlin/com/shared/security/application/usecases/RunKekHealthCheckUseCase.kt).

## Backup verification

`KekBackupVerifyJob` runs daily (configurable via
`SECURITY_KEK_BACKUP_VERIFY_INTERVAL_HOURS`). Calls
`KekBackupVerifierPort.verify()` which attempts to decrypt a known probe blob against the
offsite KEK backup. Stream C ships a [`NoOpKekBackupVerifier`](../infrastructure/src/main/kotlin/com/shared/security/infrastructure/kek/NoOpKekBackupVerifier.kt)
that always succeeds — Stream E wires the real verifier once the offsite store vendor is
selected.

Three outcomes:

- `Ok(backupKekId)` → `KEK_BACKUP_VERIFIED` audit row with `success=true`.
- `CorruptBackup(backupKekId, reason)` → `KEK_BACKUP_VERIFY_FAILED` audit row with
  `success=false`. **This is an emergency** — primary + backup divergence means a primary
  failure leaves DEKs unrecoverable.
- `TransientFailure(reason)` → no audit row; next tick retries.

## Scheduler configuration

Every interval is env-var configurable. The full list is in
[`SchedulerConfig.kt`](../adapters/inbound/scheduler/src/main/kotlin/com/shared/security/adapters/inbound/scheduler/SchedulerConfig.kt):

| Env var | Default | Purpose |
|---------|---------|---------|
| `SECURITY_SCHEDULER_ENABLED` | `false` | Master switch. `false` means no jobs fire. Stream E flips to `true` in prod env. |
| `SECURITY_KEK_HEALTH_INTERVAL_MINUTES` | `60` | KekRotationHealthJob |
| `SECURITY_KEK_PRIOR_TTL_INTERVAL_MINUTES` | `60` | KekPriorTtlJob |
| `SECURITY_DEK_ROTATION_INTERVAL_MINUTES` | `10_080` (weekly) | DekRotationJob |
| `SECURITY_DEK_ROTATION_BATCH_SIZE` | `100` | Max rewraps per fire |
| `SECURITY_AUDIT_SHIPPER_INTERVAL_MINUTES` | `60` | AuditLogShipperJob |
| `SECURITY_AUDIT_RETENTION_INTERVAL_HOURS` | `24` | AuditRetentionJob |
| `SECURITY_KEK_BACKUP_VERIFY_INTERVAL_HOURS` | `24` | KekBackupVerifyJob |
| `SECURITY_KEK_QUIESCE_WINDOW_HOURS` | `24` | Minimum time a PRIOR KEK must wait before retirement |
