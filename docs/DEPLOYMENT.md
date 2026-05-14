# Deployment

How to bring up the standalone security service alongside the monolith.

## Local dev (docker-compose, Stream E)

The compose stack lives in `scaffold/docker-compose.yml`. Two new services land behind
the `security` Compose profile so existing dev workflows (`docker compose up -d`) keep
working without the security stack.

```bash
# 1. Generate certs + keys (one-time per machine; see CERT_GENERATION.md)
cd scaffold
bash ../security-service/docs/cert-generation-recipe.sh   # not provided yet — follow CERT_GENERATION.md by hand

# 2. Bring up the security stack
docker compose --profile security up -d

# 3. Wire the monolith to use the remote crypto path
# Edit scaffold/.env:
SECURITY_SERVICE_URL=https://security-app:8443
SECURITY_SERVICE_CLIENT_CERT_PATH=./secrets/security-service/monolith-client.pem
SECURITY_SERVICE_CLIENT_KEY_PATH=./secrets/security-service/monolith-client.key
SECURITY_SERVICE_CA_PATH=./secrets/security-service/ca.pem

# 4. Restart the monolith — boot log should report:
#    "CryptoKeyServicePort → RemoteCryptoKeyServiceAdapter (https://security-app:8443)"
docker compose restart app

# 5. Verify with a probe call
curl --cert ./secrets/security-service/monolith-client.pem \
     --key  ./secrets/security-service/monolith-client.key \
     --cacert ./secrets/security-service/ca.pem \
     https://localhost:8443/v1/health
# → {"status":"ok","service":"security-service"}
```

## Topology

```
┌──────────────────────────────────────────────────────────────────────┐
│ docker compose stack                                                 │
│                                                                      │
│   ┌────────────────┐   default-net    ┌──────────────┐               │
│   │ mysql          │ ◀───── reads ─── │ app          │               │
│   │ financial_db   │                  │ (monolith)   │               │
│   │ mailpit        │                  └──────┬───────┘               │
│   └────────────────┘                         │                       │
│                                              │ mTLS                  │
│                                              ▼                       │
│                                      ┌────────────────┐              │
│                                      │ app-net        │              │
│                                      └────────┬───────┘              │
│                                               │                      │
│                                       ┌───────▼───────┐              │
│                                       │ security-app  │              │
│                                       └───────┬───────┘              │
│                                               │ ONLY this lane       │
│                                       ┌───────▼───────┐              │
│                                       │ security-net  │ internal:true│
│                                       └───────┬───────┘              │
│                                               │                      │
│                                       ┌───────▼───────┐              │
│                                       │ security_db   │              │
│                                       └───────────────┘              │
└──────────────────────────────────────────────────────────────────────┘
```

Key invariants:

- `app` reaches `security-app` via **`app-net`** (the only cross-boundary lane).
- `security_db` is on **`security-net` with `internal: true`** — has no external
  connectivity. The monolith has no path to it.
- The default network keeps existing `app ↔ mysql / financial_db / mailpit` traffic
  unchanged.

## Secrets layout

Five files, all gitignored under `scaffold/secrets/security-service/`. See
[`CERT_GENERATION.md`](CERT_GENERATION.md) for the generation recipes.

| Secret | Mounted at | Owner |
|--------|-----------|-------|
| `keystore.p12` | `/run/secrets/security-service/keystore.p12` | `security-app` (server cert + key) |
| `truststore.p12` | `/run/secrets/security-service/truststore.p12` | `security-app` (CA for verifying client certs) |
| `ml_kem_public_key` | `/run/secrets/security-service-kek/ml_kem_public_key` | `security-app` (KEK material) |
| `ml_kem_private_key` | `/run/secrets/security-service-kek/ml_kem_private_key` | `security-app` (KEK material) |
| `audit_hmac_key` | `/run/secrets/audit_hmac_key` | `security-app` (HMAC chain) |
| `monolith-client.pem` + `.key` + `ca.pem` | mounted into the monolith via `scaffold/secrets/security-service/` | `app` (mTLS client material) |

The monolith's client cert + key are read from the host filesystem path the operator
sets in `SECURITY_SERVICE_CLIENT_CERT_PATH` / `_KEY_PATH` / `_CA_PATH`. They are NOT
docker secrets on the `app` service — keeping them as host-mounted files makes them
easy to rotate without rebuilding the image.

## K3s production topology (proposal §3.4)

Two namespaces:

```
namespace/app                          namespace/security
├── deployment/app                     ├── deployment/security-app  (≥ 2 replicas)
├── service/app  (ClusterIP)           ├── deployment/security-mysql (statefulset)
└── ingress/app  (public, Linkerd)     └── service/security-app  (ClusterIP, mesh-only)
```

- **Linkerd service mesh** terminates mTLS at each pod's sidecar. The application layer
  receives the verified subject from the Linkerd identity header; the
  `PeerCertChainExtractor` implementation in Stream E reads it from there rather than
  from a Netty SSL session.
- **No public ingress to `security-app`.** The service is reachable only from within the
  cluster, and only via the Linkerd mesh.
- **Network policies** enforce: `namespace/app` pods may reach `namespace/security`
  service `security-app`. Nothing in `namespace/app` may reach `security-mysql`.
- **`KEK_MOUNT_DIR`** is a `Secret` volume backed by either Kubernetes `Secret` (dev
  posture) or an HSM-backed secret store (FedRAMP posture).
- **`AUDIT_HMAC_KEY`** and **`BACKUP_KEY`** are separate `Secret` volumes — never the
  same secret as the KEK material (per proposal §10).

The k3s-specific manifests are out of scope for Stream E and arrive in a Phase 14
follow-on once cluster networking is finalised.

## Monolith opt-in cutover (Stream E + post-E)

The monolith stays compatible with both the legacy in-process path and the new remote
path. The boot-time `resolveCryptoKeyService` (in `AppModule.kt`) picks one based on env:

1. `SECURITY_SERVICE_URL` set → `RemoteCryptoKeyServiceAdapter` ✅ Phase 14 prod path
2. `SECURITY_SERVICE_MODE=local-dev` + `ML_KEM_*` → `LocalDevCryptoKeyServiceAdapter`
3. neither → `NoOpCryptoKeyService` (fail-closed)

The cutover sequence:

1. **Bring up the security stack** (`docker compose --profile security up -d`). Existing
   monolith is unchanged.
2. **Import legacy DEKs** with `security-service-cli import-monolith-deks` (SKS-E02).
   The CLI is idempotent — re-running it is a no-op.
3. **Run `LegacyEnvelopeRewriteJob`** (SKS-E03) to convert every `enc:v0:` / `enc:v2:`
   row to `enc:v3:<dek_handle>:<bytes>`. Bounded per-cycle; resumable.
4. **Set `SECURITY_SERVICE_URL`** on the monolith. Restart. The monolith now routes
   every wrap/unwrap through `security-app`.
5. **Verify** the audit chain on `security-app` shows live traffic from the monolith's
   client cert subject DN.
6. **(After dwell)** drop the monolith's `principal_encryption_keys` table (SKS-E04).
   This step is intentionally **outside Flyway** — a tripwire migration breaks every
   dev boot that hasn't set a confirmation flag, which is worse than a manual SQL
   drop. Operator runs:

   ```bash
   docker compose exec mysql mysql -uroot -p${MYSQL_ROOT_PASSWORD} workautomations \
     -e "DROP TABLE principal_encryption_keys"
   ```

   Pre-flight checklist before issuing the DROP:
   - [ ] `LegacyEnvelopeRewriteJob` has reported `completed_at != NULL` for every row
         in `legacy_envelope_rewrite_state` (SQL: `SELECT * FROM legacy_envelope_rewrite_state WHERE completed_at IS NULL` returns no rows).
   - [ ] No production traffic is hitting the legacy read path. Check
         `security_keys.audit_events`: every `DEK_UNWRAPPED` event for the last hour
         has `actor_subject` matching the monolith's mTLS subject DN (no rogue callers).
   - [ ] A point-in-time backup of the monolith DB has been taken.

7. **(After dwell)** delete `MlKemService` + `MlKemCryptoKeyService` from `scaffold/`
   (SKS-D04 + SKS-E05). ArchUnit rule **M-1** (Stream F) prevents reintroduction.

Steps 6–7 are explicitly deferred to a separate operator action because they are
one-way — the in-process path becomes unrecoverable without a code restore.
