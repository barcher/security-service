# Migrations

Flyway migrations for the security service's own MySQL. Location:
`adapters/outbound/persistence/src/main/resources/security-db/migration/`. Runs on startup
when `SECURITY_DB_ENABLED=true`; no-op otherwise.

## Index

| Version | File | Purpose |
|---------|------|---------|
| V1 | `V1__keks.sql` | `keks` table — KEK lifecycle state machine |
| V2 | `V2__deks.sql` | `deks` table — wrapped DEK store, keyed by opaque handle |
| V3 | `V3__audit_events.sql` | `audit_events` table — HMAC-SHA-512 chained audit log |

## V1 — `keks`

Stores one row per ML-KEM-768 keypair the service has known about, driving the
STAGED → ACTIVE → PRIOR → RETIRED state machine. Key bytes are NOT in this table — they
live in memory only, loaded by `FileMountKekProvider` from a mounted secret. The schema
holds the SHA-256 fingerprint (95-char colon-hex) and lifecycle timestamps so audit
references stay durable even after a KEK is retired.

**Singleton-ACTIVE invariant** is enforced by a generated column + unique index:

```sql
ALTER TABLE keks
    ADD COLUMN active_singleton_marker TINYINT GENERATED ALWAYS AS (
        CASE WHEN status = 'ACTIVE' THEN 1 ELSE NULL END
    ) STORED,
    ADD UNIQUE KEY uk_keks_one_active (active_singleton_marker);
```

A second INSERT with `status = 'ACTIVE'` fails the unique index. PRIOR rows are allowed in
arbitrary count.

## V2 — `deks`

Stores one row per opaque `dek_handle` issued by `POST /v1/dek/generate`. `kek_id` FK
references `keks(id)` with `ON DELETE RESTRICT` — you cannot delete a KEK that has live
DEKs.

`wrapped_dek_bytes_pending` is populated by `DekRotationJob` during a rotation cycle and
atomically promoted to `wrapped_dek_bytes` once verified. Stream C ships the schema; the
two-phase atomic promotion ships with the production rotation hardening in a Stream F
follow-on.

## V3 — `audit_events`

HMAC-SHA-512 chained audit log per proposal §10. Every write goes through
`ExposedAuditLogRepository`, which:

1. Locks the latest row (`SELECT row_hmac FROM audit_events ORDER BY id DESC LIMIT 1 FOR UPDATE`)
2. Computes `row_hmac = HMAC-SHA-512(AUDIT_HMAC_KEY, canonical_payload ‖ prev_hmac)`
3. INSERTs the new row with that `row_hmac`

`prev_hmac` for row N is `row_hmac[N-1]`; for the first row it is the zero-byte sentinel
in `AuditChainHasher.INITIAL_PREV_HMAC`. The `canonical_payload` encoding is
length-prefixed (NOT JSON) so two payloads with identical logical content always produce
the same HMAC — see [`AUDIT_LOG.md`](AUDIT_LOG.md) for the full encoding.

## Operating procedure

```bash
# Apply migrations explicitly (idempotent; only un-applied versions run):
./gradlew :adapters:outbound:persistence:integrationTest --tests "*SecurityFlywayMigrationTest*"

# Manual inspection (requires Docker; SECURITY_DB_ENABLED=true):
docker compose exec security-mysql mysql -uroot -proot security_keys \
    -e "SELECT version, description, success FROM flyway_schema_history ORDER BY installed_rank;"
```

## Adding a new migration

1. Add `V<n+1>__<purpose>.sql` to `adapters/outbound/persistence/src/main/resources/security-db/migration/`.
2. Update this file's Index table. The `docs/README.md` allowlist requires `MIGRATIONS.md`
   to exist — adding a new V is an in-file edit, NOT a new file.
3. Never alter an existing committed migration. If a schema change is needed, write a new
   migration that does the change.
4. Run `./gradlew :adapters:outbound:persistence:integrationTest` to validate against a
   Testcontainers MySQL.
