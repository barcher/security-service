# Security scorecard

Operator-facing snapshot of the security service's posture. Each row maps a security
control to (a) the current implementation status, (b) the source-of-truth code/doc, and
(c) the FIPS / FedRAMP control family it satisfies.

This file is kept current per ticket: each stream's tickets either toggle a status from
**Planned** / **Partial** to **Implemented**, or add a new row. ArchUnit rule **S-7**
(Stream F) blocks the addition of any new doc that isn't in `docs/README.md`'s allowlist.

> Re-graded at each stream's close. **Last update:** Stream G kickoff — `EncryptedColumnWriter`
> facade introduced (P14.1 sibling-column threading). Reader implements the three-step
> rule (proposal §7.1.1). Canonical V112 sibling-column migration template landed for
> `principal_dining_sessions`; SKS-G03..G09 follow the template per-table. SKS-G01
> schema linter present but `@Disabled` until SKS-G09 lands — code review owns the
> "new encrypted column needs siblings" check until then.

## Posture summary

| Dimension | Score | Status as of Stream D |
|-----------|-------|------------------------|
| **Key isolation** | A | KEK held in memory only; mounted via `FileMountKekProvider`; never on disk in plaintext; **Stream D**: monolith never imports `MlKemService` directly in prod-wired paths — only `RemoteCryptoKeyServiceAdapter` reaches the KEK. **Stream E follow-up (TRUST_MODEL.md)**: architecture pre-wired for HSM-rooted prod via the `KekProvider` interface seam; prod replaces `FileMountKekProvider` with `HsmUnwrappingKekProvider` calling PKCS#11 without touching any application-layer use case. Root CA private key never exists as bytes outside the physical HSM in prod. |
| **Algorithm modernity** | A | ML-KEM-768 (FIPS 203) + HKDF-SHA-512 + AES-256-GCM. TLS 1.3 + ECDSA P-384 on both server (security-service) and client (monolith `RemoteCryptoKeyServiceAdapter`). No legacy fallback. |
| **Audit integrity** | A | HMAC-SHA-512 row chain keyed by independent `AUDIT_HMAC_KEY`. Chain-break is structural tamper evidence. **SKS-E08 (2026-05-15):** `SECURITY_DB_ENABLED` default flipped from `false` to `true` — the in-memory SLF4J fallback is now an explicit opt-out, not a silent default; operators no longer get a tamper-evidence-free audit log when they forget to set the env var. |
| **Authentication** | A | mTLS on every endpoint, including `/v1/health`. **Stream D**: monolith-side client is wired via `RemoteCryptoKeyServiceAdapter` — TLS 1.3 only, ECDSA P-384, exponential-backoff retry, fail-closed on connection error. **SKS-E07 (2026-05-15)**: the Stream-E intent is fully realized — `Application.kt::buildServer` installs a Ktor `sslConnector` with the configured keystore + truststore (mTLS-required at the Netty handshake layer), and `NettySslPeerCertChainExtractor` reads the validated chain from the Netty `SslHandler` SSL session for `MtlsAuthPlugin` to consume. The `DenyAllPeerCertChainExtractor` remains as the fail-closed fallback when `MtlsConfig.fromEnv()` returns null. |
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

### Stream F — Boundary enforcement + documentation lock-in

| Control | Implementation | Reference |
|---------|----------------|-----------|
| Monolith M-1..M-6 ArchUnit suite — runs in CI | `CryptoModuleOutwardBoundaryTest.kt` (extended to 8 rules, 8 tests) | `scaffold/infrastructure/src/test/.../security/` |
| Security-service S-4..S-8a ArchUnit suite | `SecurityBoundaryArchTest.kt` (5 rules) | `security-service/infrastructure/src/test/.../infrastructure/` |
| Cross-repo CryptoKeyServicePort.kt byte-identity (S-9) | `CryptoKeyServicePortIdentityTest.kt` (JUnit, skips when scaffold not co-checked-out) | same |
| Docs allowlist enforcement (S-7) | `DocsAllowlistTest.kt` — 3 tests cover present/missing/no-subdirs invariants | same |
| ARCHITECTURE.md kept in sync across `scaffold/docs/` and `meta-project/context/` | §14 added with identical content; mirroring is mandated by CLAUDE.md "Ongoing documentation concern" rule | `scaffold/docs/ARCHITECTURE.md` §14 + `meta-project/context/ARCHITECTURE.md` §14 |
| k3s deployment proposal includes Phase 14 amendment | §0 prepended: 2-namespace layout, Linkerd mesh, 4 explicit NetworkPolicies, no public ingress to security-app | `scaffold/docs/proposals/k3s_self_hosted_deployment.md` §0 |
| CLAUDE.md Phase 14 rule current-state subsection | Operators reading the rules cold know which rules are pre-cutover vs post-cutover | `meta-project/CLAUDE.md` "Shared Key Service" §current-state |
| Pre-cutover legacy reference set is explicit + small | `PHASE_14_LEGACY_EXEMPTIONS = { Application.kt, AppModule.kt, FinancialModule.kt, DekWrappedStringEncryptor.kt }` — 4 files, each tied to an SKS-D04/E05 deletion | `CryptoModuleOutwardBoundaryTest.kt` |

**FedRAMP mapping:** CM-2 (baseline configuration — boundary rules are the baseline), CM-4 (security impact analysis — every commit's diff is checked against M-1..M-6 / S-4..S-9), SI-7 (software / firmware integrity — cross-repo port byte-identity catches drift).

### Stream G (P14.1) — Envelope-format sibling columns

| Control | Implementation | Reference |
|---------|----------------|-----------|
| Schema linter for paired sibling columns | `EncryptedColumnSchemaLinterTest` — enabled as of SKS-G09; forward-only guard fails build on any new encrypted column without paired siblings | `scaffold/adapters/outbound/persistence/src/test/.../EncryptedColumnSchemaLinterTest.kt` |
| `EncryptedColumnWriter` facade — 3-step reader rule | Sibling → prefix → plaintext (fail-closed on registered-encrypted with neither) | `scaffold/application/.../ports/EncryptedColumnWriter.kt` + `scaffold/infrastructure/.../security/DekWrappedEncryptedColumnWriter.kt` |
| Producer always emits envelope-format sibling | Writer returns `EncryptedTriplet(ciphertext, "v0" \| "v4", dek_handle?)` for encrypted columns | same |
| Canonical sibling-column migrations | V112 (dining_sessions), V113 (RTVA + briefs + AI prompts + audit + investor + team-roles + calendar + hiring suite), V114 (inbox / resume / travel / framing) | `scaffold/infrastructure/src/main/resources/db/migration/V112-V114__*.sql` |

**FedRAMP mapping:** SC-28 (info at rest — adding format/handle siblings prepares for opaque ciphertext without sacrificing readability during transition), CM-3 (configuration change control — every new encrypted column requires a paired-column migration; enforced post-G09).

### Stream H (P14.2) — Prefix-less writes + envelope migration

| Control | Implementation | Reference |
|---------|----------------|-----------|
| Wire-version selector (env-gated) | `EncryptorWireVersion` enum + `ENCRYPTOR_WIRE_VERSION` env var; default `v3`, opt-in `v4` | `scaffold/application/.../ports/EncryptorWireVersion.kt` |
| Prefix-less v4 write path | `DekWrappedEncryptedColumnWriter.writeV4` — base64(iv ‖ ct ‖ tag), no `enc:` prefix; mints DEK handle via `DekHandleResolver` port | `scaffold/infrastructure/.../security/DekWrappedEncryptedColumnWriter.kt` |
| v4 reader | `readOpaqueV4` — uses `<col>_dek_handle` to fetch DEK via wired `v4DekFetcher`; null-handle fails closed | same |
| Reader rule — legacy tolerance | `readFrom` falls through to legacy `enc:v0:` / `enc:v3:` parser when `envelope_format != 'v4'` | same |
| Invariant guard — H04 | `DekWrappedEncryptedColumnWriterV4Test.H04 invariant` asserts v4 ciphertext never starts with `enc:` (covers plaintext that itself contains `enc:` substring) | `scaffold/infrastructure/src/test/.../DekWrappedEncryptedColumnWriterV4Test.kt` |
| `EnvelopeMigrationToV4Port` — per-column rewriter port | Distinct from Stream-E `LegacyEnvelopeRewriterPort`; targets v0/v2/v3 → v4 | `scaffold/application/.../ports/EnvelopeMigrationToV4Port.kt` |
| `RunEnvelopeMigrationToV4UseCase` — driver | Bounded batch (default `perColumnBatch=500`, `totalBatchCeiling=5000`/fire); state namespaced `v4:<table>` in `legacy_envelope_rewrite_state`; error isolation per column | `scaffold/application/.../principal/RunEnvelopeMigrationToV4UseCase.kt` |
| `EnvelopeMigrationJob` — Quartz | `@DisallowConcurrentExecution`; structured logging; idempotent per row | `scaffold/adapters/inbound/scheduler/.../EnvelopeMigrationJob.kt` |

**FedRAMP mapping:** SC-13 (cryptographic protection — the v4 envelope keeps AES-256-GCM but eliminates the in-band format prefix, which was metadata leakage), CM-3 (configuration change control — wire-version toggle is reversible until cutover; rollback path documented), SI-7 (software integrity — H04 invariant guard fails the build on any regression that re-introduces an in-band prefix on the v4 path).

**Stream H02b (per-column rewriter SQL adapters):** generic `GenericEnvelopeRewriterToV4` + `EnvelopeMigrationRowAccessPort` + `ExposedEnvelopeMigrationRowAccessAdapter` (defence-in-depth identifier validation via `[a-z][a-z0-9_]{0,63}` regex) + auto-discovery `EnvelopeRewriterRegistry` that materialises one rewriter per row in `principal_column_encryption_config`. State persisted via `ExposedLegacyEnvelopeRewriteStateRepository`. Quartz job wired in `Application.configureScheduler` to fire every 10 minutes. 10 use-case + 4 registry unit tests pass.

### Stream I (P14.3) — Reader-deletion cutover (partial — operator-gated)

| Control | Implementation | Reference |
|---------|----------------|-----------|
| Migration-completion gate use case | `CheckEnvelopeMigrationStatusUseCase` — sums `COUNT(*) WHERE envelope_format IS NULL OR != 'v4'` across every registered encrypted column | `scaffold/application/.../principal/CheckEnvelopeMigrationStatusUseCase.kt` |
| Migration-completion gate route | `GET /api/security/envelope-migration-status` — ACCOUNT_OWNER only; returns `{complete, totalRemaining, columns[]}`; read-only + idempotent | `scaffold/adapters/inbound/http/.../PrincipalEnvelopeMigrationRoutes.kt` |
| ArchUnit M-9 (transitional) | `CryptoModuleOutwardBoundaryTest` forbids `"enc:v"` literal in `infrastructure/security/` outside `STREAM_I_LEGACY_EXEMPTIONS`; exemption list currently covers `DekWrappedStringEncryptor.kt` + `DekWrappedEncryptedColumnWriter.kt` and is removed at SKS-I02 cutover | `scaffold/infrastructure/src/test/.../CryptoModuleOutwardBoundaryTest.kt` |

**FedRAMP mapping:** AU-2 (auditable events — gate endpoint is the operator's checkable verification step before reader deletion), CM-3 (configuration change control — the gate's `complete=true` return is the formal sign-off before SKS-I02 lands), SI-7 (software integrity — M-9 guards against accidental re-introduction of the in-band wire-format prefix).

**Operator-gated (deferred):** SKS-I02 (legacy prefix-branch deletion in `DekWrappedEncryptedColumnWriter.readFrom`) and SKS-I04 (test fixture cleanup) land in a single follow-up PR once the operator confirms `GET /api/security/envelope-migration-status` returns `complete=true` in production. This gate is enforced operationally, not in code, because the migration job itself depends on the legacy reader to bridge `enc:v0:` rows to v4 — landing SKS-I02 before migration completion would prevent any further v4 conversions.

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
