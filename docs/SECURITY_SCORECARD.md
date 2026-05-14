# Security scorecard

Operator-facing snapshot of the security service's posture. Each row maps a security
control to (a) the current implementation status, (b) the source-of-truth code/doc, and
(c) the FIPS / FedRAMP control family it satisfies.

This file is kept current per ticket: each stream's tickets either toggle a status from
**Planned** / **Partial** to **Implemented**, or add a new row. ArchUnit rule **S-7**
(Stream F) blocks the addition of any new doc that isn't in `docs/README.md`'s allowlist.

> Re-graded at each stream's close. **Last update:** Stream E in flight — docker-compose
> stack (security-app + security_db on named networks), DEK import CLI, monolith-side
> `LegacyEnvelopeRewriteJob` + state table (V111). KEK material moves from env vars to
> docker secrets at `/run/secrets/security-service-kek/`. The `principal_encryption_keys`
> table drop is documented as an operator step (§6 of DEPLOYMENT.md) rather than a
> Flyway tripwire — safer dev posture.

## Posture summary

| Dimension | Score | Status as of Stream D |
|-----------|-------|------------------------|
| **Key isolation** | A | KEK held in memory only; mounted via `FileMountKekProvider`; never on disk in plaintext; **Stream D**: monolith never imports `MlKemService` directly in prod-wired paths — only `RemoteCryptoKeyServiceAdapter` reaches the KEK. |
| **Algorithm modernity** | A | ML-KEM-768 (FIPS 203) + HKDF-SHA-512 + AES-256-GCM. TLS 1.3 + ECDSA P-384 on both server (security-service) and client (monolith `RemoteCryptoKeyServiceAdapter`). No legacy fallback. |
| **Audit integrity** | A | HMAC-SHA-512 row chain keyed by independent `AUDIT_HMAC_KEY`. Chain-break is structural tamper evidence. |
| **Authentication** | A− | mTLS on every endpoint, including `/v1/health`. **Stream D**: monolith-side client is wired via `RemoteCryptoKeyServiceAdapter` — TLS 1.3 only, ECDSA P-384, exponential-backoff retry, fail-closed on connection error. **Caveat:** real cert-chain *extractor* on the server still lands in Stream E (deny-all default in `SecurityServiceModule`). |
| **Authorization** | A | Admin endpoints gated on `AdminAllowList` subject DN; ADMIN_FORBIDDEN audit on every reject. |
| **Rate limiting** | B+ | Per-subject token bucket on `/v1/dek/unwrap`. **Caveat:** local-process state — multi-replica scale-out requires a shared limiter (Stream F follow-on). |
| **Audit retention** | A | 7-year retention floor (FedRAMP AU-11). Cold-storage gate prevents deletion before mirror confirmation. |
| **KEK rotation** | B | State machine implemented (STAGED → ACTIVE → PRIOR → RETIRED) with automatic retirement. **Caveat:** activation is operator-driven; automatic activation lands in Stream F. |
| **Backup verification** | C | `KekBackupVerifyJob` infrastructure in place. **Caveat:** Stream-C wires a `NoOpKekBackupVerifier` that always returns Ok — real backup-store integration lands in Stream E. |
| **Network topology** | A− | **Stream E**: docker-compose stack uses named networks (`app-net`, `security-net` with `internal: true`). Monolith reaches `security-app` only via `app-net`; `security_db` has no path to anything except `security-app` via internal `security-net`. **Caveat:** k3s Linkerd mesh manifests still pending a follow-on. |

## Controls

### Cryptographic algorithms

| Component | Algorithm | Reference |
|-----------|-----------|-----------|
| KEK | ML-KEM-768 (FIPS 203) | `adapters/outbound/crypto/MlKemService.kt` |
| DEK wrap | HKDF-SHA-512 over ML-KEM shared secret → AES-256-GCM with AAD | `MlKemService.kt` §`wrapBytes` |
| AEAD | AES-256-GCM, 12-byte IV, 16-byte tag, AAD-bound | same |
| DEK size | 32 bytes (256-bit) | `MlKemService.DEK_BYTES` |
| TLS | 1.3 only, ECDSA P-384 client + server certs | `infrastructure/tls/MtlsConfig.kt` |
| Audit chain | HMAC-SHA-512, 64-byte digest, key ≥32 bytes | `adapters/outbound/persistence/audit/AuditChainHasher.kt` |

**FIPS posture:** every primitive above is FIPS 140-3 approved (FIPS 197 / 198-1 / 180-4 / 203).
The implementation uses BouncyCastle (`bcprov-jdk18on:1.80`) and the JVM's built-in JCA. A
FedRAMP attestation requires switching to a FIPS-validated BC build (`bc-fips`); this is a
build-time substitution, not a code change, and lands in Stream F.

### Key independence

The service holds three secrets, each independent of the others:

| Secret | Used for | Where loaded |
|--------|----------|--------------|
| `ML_KEM_PRIVATE_KEY` / `ML_KEM_PUBLIC_KEY` | KEK wrap/unwrap | `FileMountKekProvider` (mounted directory; not env vars) |
| `AUDIT_HMAC_KEY` | Audit log row chain HMAC | `AuditHmacKeyProvider.fromEnv` (env / mounted secret) |
| `BACKUP_KEY` | Encryption of offsite KEK backup blobs | (Stream E) |

Independence is **structural**, not aspirational: a leak of any one secret does not
compromise the others. The audit chain HMAC key is never used to wrap DEKs; the backup
key is never derived from the KEK.

Reference: [`AUDIT_LOG.md`](AUDIT_LOG.md), [`KEK_LIFECYCLE.md`](KEK_LIFECYCLE.md).

### Authentication + authorization (server side)

| Control | Implementation | Reference |
|---------|----------------|-----------|
| mTLS gate before routing | `installMtlsAuth` interceptor in `Plugins` phase | `adapters/inbound/http/auth/MtlsAuthPlugin.kt` |
| Audit on auth fail | `MTLS_REJECTED` audit row + HTTP 401 | same |
| Cert fingerprint logging | SHA-256 of leaf cert into `ClientPrincipal` | `auth/ClientPrincipal.kt` |
| Admin allow-list | RFC2253 subject DN match (`SECURITY_ADMIN_SUBJECTS` env) | `application/ports/AdminAllowList.kt` |
| Audit on authz fail | `ADMIN_FORBIDDEN` audit row + HTTP 403 | `adapters/inbound/http/AdminRoutes.kt` |

### Monolith client (Stream D)

| Control | Implementation | Reference |
|---------|----------------|-----------|
| HTTPS only — non-HTTPS URL rejected at boot | `RemoteCryptoKeyServiceConfig.init` `require(baseUrl.startsWith("https://"))` | `scaffold/.../RemoteCryptoKeyServiceConfig.kt` |
| TLS 1.3 binding at SSLContext | `SSLContext.getInstance("TLSv1.3")` | `scaffold/.../RemoteCryptoKeyServiceSslContext.kt` |
| ECDSA P-384 client cert (PEM) | PKCS#8 PEM loaded via BC PEMParser; encrypted PEM rejected | same |
| JVM default truststore NOT consulted | Only the configured CA bundle is trusted via custom `TrustManagerFactory` | same |
| Fail-closed on connection error | `RemoteCryptoKeyServiceAdapter.ensureOk` throws `CryptoServiceUnavailable` on 5xx + non-OK | `scaffold/.../RemoteCryptoKeyServiceAdapter.kt` |
| Exponential-backoff retry on transient failures | Ktor `HttpRequestRetry` plugin; default 3 retries; bounded by config | same |
| Mode resolution logged at boot | `cryptoModeLogger.info(...)` reports the bound adapter | `scaffold/.../infrastructure/di/AppModule.kt` `resolveCryptoKeyService` |
| Local-dev mode loud warning | `LocalDevCryptoKeyServiceAdapter.init { logger.warn(...) }` once per process | `scaffold/.../LocalDevCryptoKeyServiceAdapter.kt` |

**FedRAMP mapping:** IA-2 (identification), AC-3 (access enforcement), AU-2 (auditable events), SC-8 (transmission confidentiality).

### Stream E — Cutover infrastructure

| Control | Implementation | Reference |
|---------|----------------|-----------|
| Named-network isolation (`app-net` + `security-net` `internal: true`) | docker-compose stack | `scaffold/docker-compose.yml` |
| KEK material via docker secrets (NOT env vars) on prod path | `KEK_MOUNT_DIR=/run/secrets/security-service-kek` | `docker-compose.yml` security-app service |
| Server keystore + truststore mounted as docker secrets | `keystore.p12` + `truststore.p12` paths | same |
| Compose profile guard (`security` profile) prevents accidental boot | `profiles: ["security"]` on both services | `docker-compose.yml` |
| Idempotent legacy-DEK import (UNIQUE on `deks.legacy_key_id`) | V4 migration + ImportMonolithDeksCli check | `security-service/.../V4__legacy_dek_provenance.sql` |
| Legacy envelope rewriter — state-tracked, resumable | `legacy_envelope_rewrite_state` table + `RunLegacyEnvelopeRewriteUseCase` | `scaffold/.../V111__create_legacy_envelope_rewrite_state.sql` |
| Per-row JDBC transaction guarantee — partial crashes consistent | `LegacyEnvelopeRewriterPort.rewriteBatch` contract | `scaffold/.../LegacyEnvelopeRewritePort.kt` |
| `principal_encryption_keys` drop is operator-gated documented step | DEPLOYMENT.md §6 pre-flight checklist | `security-service/docs/DEPLOYMENT.md` |
| No-tripwire posture: drop is NOT a Flyway migration | (Explicit design decision — would crash every dev pull) | items.md SKS-E04 |

**FedRAMP mapping:** SC-7 (boundary protection), SC-28 (info at rest), AU-9 (audit info protection — chain remains intact across the cutover).

### Rate limiting

| Control | Implementation | Reference |
|---------|----------------|-----------|
| Per-subject token bucket on `/v1/dek/unwrap` | `PerSubjectRateLimiter` (default 5 cap, 1/s refill) | `adapters/inbound/http/ratelimit/PerSubjectRateLimiter.kt` |
| Audit on overflow | `RATE_LIMIT_EXCEEDED` audit row + HTTP 429 | `CryptoRoutes.kt` |
| Configurable via env | `SECURITY_UNWRAP_RATE_LIMIT_*` | [`RATE_LIMITING.md`](RATE_LIMITING.md) |

**Threat mapped:** T12 (oracle abuse on `/v1/dek/unwrap`) from proposal §4.

**Open gap (Stream F):** the limiter is local-process. At N replicas, per-subject effective
limit is `N × per-replica limit`. Documented in `RATE_LIMITING.md`; mitigation is to keep
N=1 in Stream C deployments.

### Audit log integrity

| Control | Implementation | Reference |
|---------|----------------|-----------|
| Tamper-evident chain | HMAC-SHA-512 row chain, prev_hmac → row_hmac | `AuditChainHasher.kt` |
| Concurrent-write safety | `SELECT … FOR UPDATE` on latest row in REPEATABLE_READ tx | `ExposedAuditLogRepository.kt` |
| Verification at read | `verifyChain(fromId, toId)` recomputes every HMAC | same |
| Chain-break detection | `AUDIT_CHAIN_BREAK` audit row + ship halt | `RunAuditLogShipperUseCase.kt` |
| Cold-storage mirror | `ColdStoragePort` (NoOp in Stream C; S3/R2 in Stream E) | `application/ports/ColdStoragePort.kt` |
| Retention floor | 7 years (configurable); deletes gated on shipped-id | `RunAuditRetentionUseCase.kt` |

**FedRAMP mapping:** AU-9 (protection of audit info), AU-11 (audit record retention).

### KEK lifecycle

| Control | Implementation | Reference |
|---------|----------------|-----------|
| Singleton-ACTIVE invariant | Schema-enforced via generated column + unique index | `V1__keks.sql` |
| Lifecycle state machine | STAGED → ACTIVE → PRIOR → RETIRED | [`KEK_LIFECYCLE.md`](KEK_LIFECYCLE.md) |
| Automatic retirement | `KekPriorTtlJob` — TTL gate + zero-DEK-reference gate | `RunKekPriorTtlUseCase.kt` |
| Automated rewrap | `DekRotationJob` — bounded batch, configurable interval | `RunDekRotationUseCase.kt` |
| Health probing | `KekRotationHealthJob` — probe wrap + unwrap hourly | `RunKekHealthCheckUseCase.kt` |
| Backup verification | `KekBackupVerifyJob` — daily probe decrypt against offsite store | `RunKekBackupVerifyUseCase.kt` |
| Backup independence | `BACKUP_KEY` separate from KEK; backup verifier port abstracted | `application/ports/KekBackupVerifierPort.kt` |

### Failure modes audited

Every failure that leaves a visible state change emits an audit row. The catalog:

| Failure | Audit event type | success |
|---------|------------------|---------|
| mTLS handshake rejected at app layer | `MTLS_REJECTED` | false |
| Authenticated caller not in admin allow-list | `ADMIN_FORBIDDEN` | false |
| Rate-limit cap exceeded | `RATE_LIMIT_EXCEEDED` | false |
| Probe DEK wrap or unwrap failure | `HEALTH_CHECK_FAILED` | false |
| DEK rotation batch raised an exception | `DEK_ROTATION_BATCH_FAILED` | false |
| Audit chain break detected | `AUDIT_CHAIN_BREAK` | false |
| Cold-storage shipper permanent failure | `AUDIT_SHIPPED` | false |
| Backup verifier reports corrupt backup | `KEK_BACKUP_VERIFY_FAILED` | false |

All of the above are queryable via the persistent audit log (Stream C onward) and feed
the cold-storage shipper. Transient failures (network blips on cold-storage ship, network
blips on backup verify) intentionally do NOT audit, so retries don't flood the chain.

## FedRAMP control crosswalk

| Control | Coverage | Notes |
|---------|----------|-------|
| AC-3 (access enforcement) | ✅ | mTLS + admin allow-list, unconditional |
| AU-2 (auditable events) | ✅ | Every privileged op writes a row |
| AU-3 (content of audit records) | ✅ | `actor_subject`, `dek_handle`, `kek_id`, `success`, `detail_json` |
| AU-9 (protection of audit info) | ✅ | HMAC-SHA-512 row chain, key independent of KEK |
| AU-11 (audit record retention) | ✅ | 7-year retention floor; cold-storage mirror before delete |
| AU-12 (audit generation) | ✅ | At the boundary where the privileged op happens (the security service itself) |
| IA-2 (identification + authentication) | ✅ | Subject DN from mTLS leaf cert |
| SC-7 (boundary protection) | ⚠️ | Stream E wires Linkerd / docker-secrets boundary; current state assumes secure pod-to-pod within k8s namespace |
| SC-8 (transmission confidentiality) | ✅ | TLS 1.3 mandatory on every endpoint |
| SC-12 (cryptographic key establishment) | ✅ | ML-KEM-768 KEM + HKDF-SHA-512 KDF |
| SC-13 (cryptographic protection) | ✅ | AES-256-GCM AEAD with AAD-bound wrap |
| SC-28 (protection of information at rest) | ✅ | DEKs wrapped under KEK; KEK at rest in mounted secret store |
| SI-7 (software integrity) | ⚠️ | Stream F adds reproducible-build attestation + signed releases |

✅ = covered as of Stream C. ⚠️ = covered structurally, partial implementation; lands in
Stream E or F per ticket roadmap.

## How to use this scorecard

- **Pre-deployment audit:** read the table above; verify every ✅ row maps to working code
  via the linked references.
- **Quarterly review:** re-grade every dimension. Status changes (e.g. Stream E flips
  Network topology B → A) update the table; the change is tracked in git history.
- **Adding a new control or removing one:** edit this file directly; the `docs/README.md`
  allowlist already covers `SECURITY_SCORECARD.md`. SKS-F01's S-7 rule enforces the
  allowlist match.
