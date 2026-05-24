# Security scorecard

Operator-facing snapshot of the security service's posture. Each row maps a security
control to (a) the current implementation status, (b) the source-of-truth code/doc, and
(c) the FIPS / FedRAMP control family it satisfies.

This file is kept current per ticket: each stream's tickets either toggle a status from
**Planned** / **Partial** to **Implemented**, or add a new row. ArchUnit rule **S-7**
(Stream F) blocks the addition of any new doc that isn't in `docs/README.md`'s allowlist.

> Re-graded at each stream's close. **Last update: 2026-05-23 — Stream K K.2 + K.3 complete (monolith mint flipped to remote ES256; legacy HS256 path deleted).**
>
> Catch-up summary since Stream G kickoff:
> - Streams G–H + SKS-G12 (22 repos wired through `EncryptedColumnWriter`) shipped.
> - SKS-H08/H09/H10/H11 + H06/H07 (frontend stale-state) shipped.
> - **shared-security-client Phase 1+2 (2026-05-22):** canonical client library extracted to `workAutomations/shared-security-client/`; monolith + financial-service consumers refactored; S-9 ArchUnit byte-identity rule retired (one canonical port, not two).
> - **Stream K K.0 foundations (2026-05-22):** v0.2 proposal approved; `jwt_signing_keys` Flyway V5 migration; `JwtSigningKeyRepository` + `JwtAudienceAllowList` ports; `KekEnvelopePort` (internal-port pattern) + `KekEnvelopeAdapter` (AAD-binding bridge); `Es256SigningService` in new `adapters/outbound/jwt-signing/` submodule; JWT event types added to `AuditEventType`; `HSM_KEY_CEREMONY.md` runbook for KEK + JWT signing keys.
> - **Stream K K.0 complete (2026-05-23):** `ExposedJwtSigningKeyRepository` + integration test (Testcontainers MySQL); `EnvJwtAudienceAllowList` with subject-DN-hash env-var schema; three use cases (`Generate`, `Activate`, `Sign`) + three Quartz jobs (health hourly, prior-TTL daily, retention daily); `POST /v1/jwt/sign` + `GET /v1/jwks` HTTP routes wired in `Application.kt`; operator CLI subcommands `jwt-keys generate-pair` + `jwt-keys activate`; SecurityServiceModule DI binds the full chain (shared `SecurityDatabase` across audit + JWT); ArchUnit rules **S-11** (jwt-signing module isolation), **S-12** (jwt use cases never import `CryptoKeyServicePort`), **S-13** (`KekEnvelopePort` has exactly one implementer); operator + cutover runbooks shipped (`JWT_OPERATIONS.md`, `JWT_KEY_LIFECYCLE.md`, `JWT_CUTOVER.md`) + added to docs allowlist; end-to-end Testcontainers integration test exercises generate → activate → sign → local-verify against ML-KEM-768 KEK + stored SPKI.
> - **Stream K K.1 complete (2026-05-23):** consumer-side dual-stack verify path lives in `workAutomations/shared-security-client/src/main/kotlin/com/shared/security/client/jwt/` — `TokenServiceClient` port, `JwksDocumentCache` interface + `HttpJwksDocumentCache` (hourly tick + on-`kid`-miss refresh + stale-OK + exp backoff), `LocalJwksVerifierAdapter` (ES256-only, hard-rejects `alg=none|HS*|RS*`, 5s clock skew), `NoOpTokenServiceClient` fail-closed default, `JwtClientConfig` + `resolveTokenServiceClient()`. Monolith carves `LegacyHs256JwtVerifier` out of `JwtTokenService` and ships a `DualStackJwtAuthProvider` that dispatches on the JWS `kid` header → ES256 shared-client verify or legacy HS256 verify. JWKS refresh coroutine wired in `Application.configureJwksRefresh`. Refresh-token entropy bumped 32→64 bytes per K-amend-6. ArchUnit ratchets: **SC-5** (jwt/ ↛ crypto/ and vice versa in shared client), **M-11** (`LegacyHs256JwtVerifier` constructor calls only from `AppModuleKt`), **M-13** (no monolith class re-implements `TokenServiceClient`). 33 shared-client tests + 3 monolith K.1 tests, all passing. Mint path is unchanged — still HS256 — that flips in K.2.
> - **Stream K K.2 complete (2026-05-23):** monolith mint path flipped to remote. Shared-client gained `JwtSignRequest` + `JwtSignResult`, `RemoteTokenServiceAdapter` (mTLS POST `/v1/jwt/sign`, no retries on sign), `LocalDevTokenServiceClient` (in-process ES256 keypair for dev), `CompositeTokenServiceClient` (verify + sign halves wired together). `TokenServicePort.generateAccessToken` is now `suspend`. Monolith ships `RemoteJwtTokenServiceShim` implementing `TokenServicePort` via `TokenServiceClient.sign()`; `RefreshTokenGenerator` carved out (refresh tokens stay local per Shared Key Service rule 17). Issue-path metrics: `jwt_issue_algorithm_total{algorithm,outcome}` + `jwt_issue_latency_seconds`. **K-amend-6 RefreshTokenCleanupJob** (Quartz, daily 03:00 UTC, batch-ceiling 50 000 in 1000-row chunks, audit `REFRESH_TOKEN_CLEANUP_RUN`, `refresh_token_cleanup_*` metrics). 11 RemoteAdapter tests + 2 LocalDev tests + 6 cleanup-use-case tests + integration test, all passing.
> - **Stream K K.3 complete (2026-05-23 — operator gate overridden per user direction):** `JwtTokenService`, `LegacyHs256JwtVerifier`, `JwtConfig.secret`, `JWT_SECRET` env var, `JwtTokenServiceRefreshTokenEntropyTest`, and `DualStackJwtAuthProvider` deleted. New `EsJwtAuthProvider` is ES256-only; verify metric `jwt_verify_algorithm_total{algorithm="HS256"}` now always 0 (kept exporting as a smoke alarm). `TokenServicePort.validateToken` removed. WebSocket query-string auth (`WebSocketRoutes`, `financialWebSocketRoute`) refactored to verify through the shared-client `TokenServiceClient`. ArchUnit ratchet tightened: **M-11 retired** (verifier deleted), **M-10 armed** with `STREAM_K_LEGACY_EXEMPTIONS = emptySet()` — class-level check (`com.auth0.jwt.algorithms.Algorithm`) plus source-grep companion (`"HS256"` + `"JWT_SECRET"` string literals). M-13 unchanged. New `RefreshTokenGeneratorTest` replaces the deleted entropy test. `.env.example`, `application.conf`, `docs/API_KEYS.md` all swept of `JWT_SECRET` references. Full eval (ktlint + detekt + test + build) green.
> - **Stream L L.0 complete (2026-05-23):** read-only observability surface under `/v1/observability/`. New `DashboardObserverAllowList` port + `StaticDashboardObserverAllowList` impl gated by `SECURITY_DASHBOARD_OBSERVER_SUBJECTS` env var (separate lane from `SECURITY_ADMIN_SUBJECTS`). Four new audit event types: `DASHBOARD_OBSERVED`, `OBSERVER_FORBIDDEN`, `OBSERVABILITY_RATE_LIMIT_EXCEEDED`, `OBSERVABILITY_ERROR`. Five use cases (`ListKeks`, `ListDeks`, `ListJwtSigningKeys`, `SearchAuditEvents`, `ListRecentRotations`) all metadata-only — strip `wrappedDekBytes`, `wrappedPrivateKeyBytes`, `publicKeySpki`, `prev_hmac`, `row_hmac`. New read-side `AuditLogQueryPort` + `ExposedAuditLogQueryRepository` (write-side `AuditLogPort` unchanged). Five GET routes in `ObservabilityRoutes` — mTLS + Gate-2 allow-list + per-subject rate limit, ONE `DASHBOARD_OBSERVED` audit per call regardless of result-set size. ArchUnit ratchet: **S-14** (observation surface never imports crypto primitive ports), **S-15** (`ObservabilityRoutes` mounts only `/v1/observability/*` paths via source-grep), **S-16** (allow-list referenced only from routes + DI). `OBSERVABILITY_API.md` + `AUDIT_LOG.md` event-type catalog updated. 25 use-case unit tests + 11 ArchUnit tests, all passing.

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
| **HSM ceremony procedure (v0.2)** | Two-person observed ceremony for initial setup, rotation, emergency replacement, disposal; YubiHSM 2 default with cloud-KMS alternative documented | [`HSM_KEY_CEREMONY.md`](HSM_KEY_CEREMONY.md) |

### JWT signing-key lifecycle (Stream K — K.0 complete)

The JWT signing path mirrors the KEK lifecycle (same state machine, same audit-event
discipline, same backup expectations) with one structural addition: a narrow internal
port (`KekEnvelopePort`) isolates the JWT use cases from the wider `CryptoKeyServicePort`.

| Control | Implementation | Reference |
|---------|----------------|-----------|
| Singleton-ACTIVE invariant | Schema-enforced via generated column + unique index | `V5__jwt_signing_keys.sql` |
| Lifecycle state machine | STAGED → ACTIVE → PRIOR → QUIESCED → RETIRED | [`JWT_KEY_LIFECYCLE.md`](JWT_KEY_LIFECYCLE.md) |
| Wrapped-at-rest | Private bytes are KEK-wrapped via `KekEnvelopePort` with AAD-binding (`jwt-signing-key:<kid>`). Plaintext never touches disk outside the HSM | `KekEnvelopeAdapter.kt` |
| Cross-module isolation | JWT use cases consume `KekEnvelopePort`, NEVER `CryptoKeyServicePort` directly. `KekEnvelopeAdapter` is the exclusive bridge. ArchUnit rules S-11/S-12/S-13 enforce | `SecurityBoundaryArchTest.kt` |
| Signing primitive isolation | `Es256SigningService` lives in dedicated `adapters/outbound/jwt-signing/` submodule; never collocated with KEK/DEK crypto module | `Es256SigningService.kt` |
| HTTP surface | `POST /v1/jwt/sign` (mTLS-required) + `GET /v1/jwks` (public, 5-min cache) | [`JWT_OPERATIONS.md`](JWT_OPERATIONS.md) |
| Quartz lifecycle jobs | Health (hourly) + PRIOR-TTL (daily) + retention (daily); all `@DisallowConcurrentExecution` | [`JWT_KEY_LIFECYCLE.md`](JWT_KEY_LIFECYCLE.md) §2 |
| Operator CLI | `jwt-keys generate-pair [--activate]` + `jwt-keys activate --kid=<hex>` — same trust model as `generate-kek` | `JwtKeysCli.kt` |
| HSM ceremony procedure | Same two-person ceremony pattern as KEK; differences (algorithm, wrapping, publication) called out explicitly | [`HSM_KEY_CEREMONY.md`](HSM_KEY_CEREMONY.md) §3 |
| Caller authentication (two-gate) | Gate 1: mTLS subject DN (existing `MtlsAuthPlugin`). Gate 2: `EnvJwtAudienceAllowList.isAllowed(subjectDn, audience)` — denies cross-audience minting even with valid mTLS | `EnvJwtAudienceAllowList.kt` |
| Four-lane subject-DN separation | Operational / admin / dashboard-observer / operator-decrypt cert lanes recorded as distinct `actor_subject` prefixes for audit filtering | Proposal §3.4a |
| End-to-end integration test | Testcontainers MySQL → V5 migration → seed ACTIVE KEK → generate + activate JWT key → mint JWT → local verify against stored SPKI | `JwtSignAndJwksIntegrationTest.kt` |

### Observability surface (Stream L — L.0 complete)

Read-only dashboard surface under `/v1/observability/`. Lifecycle metadata only — no
key bytes, no audit-chain HMACs, no wrapped blobs. Four-lane subject-DN model: a
compromised dashboard observer cert can read metadata but cannot rotate, unwrap, sign,
or mint keys.

| Control | Implementation | Reference |
|---------|----------------|-----------|
| Two-gate caller auth | Gate 1: mTLS (`MtlsAuthPlugin`); Gate 2: `DashboardObserverAllowList.isObserver(subjectDn)` | `ObservabilityRoutes.kt` |
| Observer allow-list (distinct from admin) | `SECURITY_DASHBOARD_OBSERVER_SUBJECTS` env var; ArchUnit S-16 keeps the port referenced only from routes + DI | `StaticDashboardObserverAllowList.fromEnv` |
| Metadata-only DTOs | Use-case-layer projections strip `wrappedDekBytes`, `wrappedPrivateKeyBytes`, `publicKeySpki`; query-port strips `prev_hmac`/`row_hmac` | `ObservationDtos.kt` + `AuditLogQueryPort` |
| Read-side audit query port | New `AuditLogQueryPort` + `ExposedAuditLogQueryRepository` — write side (`AuditLogPort`) is untouched, so observers cannot mutate the chain | `AuditLogQueryPort.kt` |
| Rate limit | Per-subject token bucket; shares the same `SECURITY_RATE_LIMIT_*` config as `/v1/dek/unwrap` for K.0 | `ObservabilityRoutes.handle()` |
| Audit emission | ONE `DASHBOARD_OBSERVED` per call regardless of result-set size; 403 → `OBSERVER_FORBIDDEN`; 429 → `OBSERVABILITY_RATE_LIMIT_EXCEEDED`; 500 → `OBSERVABILITY_ERROR` | each L use case |
| Cross-module isolation | ArchUnit S-14: observation surface never imports `CryptoKeyServicePort` / `KekEnvelopePort` / `JwtSigningKeyPort`. S-15: source-grep confirms `/v1/observability/*`-only mounts. | `SecurityBoundaryArchTest` |

| Dimension | Score | Notes |
|-----------|-------|-------|
| **Observability surface** | B+ | All structural invariants in place; caveat: shares the per-subject rate-limit bucket with `/v1/dek/unwrap` (a future stream may add a dedicated `SECURITY_OBSERVABILITY_RATE_LIMIT_*` family). |

### Cross-cutting — shared-security-client library (2026-05-22)

Phase 1+2 of the `shared_security_client.md` proposal extracted the canonical base
client out of `scaffold/` (monolith) and `financial-service/` (sibling) into
`workAutomations/shared-security-client/`. Stream K K.1+ JWT client adapters extend
the same library with a `jwt/` sub-package.

| Control | Implementation | Reference |
|---------|----------------|-----------|
| Single source of truth for wire DTOs | `WrappedDek`, `KekPair`, JSON wire schema live in `shared-security-client/`; consumers depend via Gradle composite build | `shared-security-client/src/main/resources/wire-schema/security-client-v1.json` |
| Consumer independence (ArchUnit) | `ConsumerIndependenceArchTest` fails build if the shared module imports any consumer-side package, Koin, Ktor server, Exposed, or BouncyCastle | `shared-security-client/src/test/.../ConsumerIndependenceArchTest.kt` |
| Per-consumer mTLS subject DN | Each consuming service mints its own client cert (`CN=workautomations-<service>,...`); security-service's allow-list distinguishes callers in audit log | (this scorecard; see Authentication row) |
| Service-specific extension model | Financial-service's vault password-wrap superset stays in `financial-service/`; the shared client provides only the base ops every consumer needs (memory rule `feedback_financial_vault_superset.md`) | Proposal §3 v0.2 |
| Retired byte-identity check | S-9 ArchUnit rule deleted post-Phase-2 — there is no longer a second port to keep in sync | (removed 2026-05-22) |

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
| JWT sign request rejected by audience allow-list (Stream K) | `JWT_AUDIENCE_FORBIDDEN` | false |
| JWT sign failed (key unavailable, sign exception) (Stream K) | `JWT_SIGN_FAILED` | false |
| JWT signing-key health-probe failed (Stream K) | `JWKS_HEALTH_CHECK_FAILED` | false |
| Observer DN not in allow-list (Stream L) | `OBSERVER_FORBIDDEN` | false |
| Observability rate-limit cap exceeded (Stream L) | `OBSERVABILITY_RATE_LIMIT_EXCEEDED` | false |
| Observability handler raised an exception (Stream L) | `OBSERVABILITY_ERROR` | false |

All of the above are queryable via the persistent audit log (Stream C onward) and feed
the cold-storage shipper. Transient failures (network blips on cold-storage ship, network
blips on backup verify) intentionally do NOT audit, so retries don't flood the chain.

Stream K adds successful-event types as well: `JWKS_KEY_GENERATED`, `JWKS_KEY_ACTIVATED`,
`JWKS_KEY_QUIESCED`, `JWKS_KEY_RETIRED`, `JWKS_KEY_DELETED`, `JWT_SIGNED`. The
`JWT_SIGNED` rows feed the K.3 operator gate (Grafana panel
`jwt_verify_algorithm_total{algorithm="HS256"}` must be flat at 0 for ≥ 24 h).

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
| SC-12 (cryptographic key establishment) | ✅ | ML-KEM-768 KEM + HKDF-SHA-512 KDF (KEK); ES256 P-256 (JWT signing — Stream K K.0 prep). Both classes covered by `HSM_KEY_CEREMONY.md` operator runbook. |
| SC-13 (cryptographic protection) | ✅ | AES-256-GCM AEAD with AAD-bound wrap; AAD now extends to JWT signing-key envelopes via `KekEnvelopePort.wrap(plaintext, aad)` (Stream K K.0) |
| SC-28 (protection of information at rest) | ✅ | DEKs wrapped under KEK; KEK at rest in mounted secret store (HSM in prod per `TRUST_MODEL.md` + `HSM_KEY_CEREMONY.md`); JWT signing-key private bytes wrapped under KEK in `jwt_signing_keys.wrapped_private_key_bytes` |
| IA-5 (authenticator management) | ✅ | ES256 (P-256) JWT issuance + ML-KEM-768 KEK lifecycle both managed via Stream K. HS256 deleted in K.3 (operator gate overridden per user direction; ArchUnit M-10 strict prevents reintroduction). |
| AU-2 (auditable events) | ✅ | Stream L L.0 added `DASHBOARD_OBSERVED`, `OBSERVER_FORBIDDEN`, `OBSERVABILITY_RATE_LIMIT_EXCEEDED`, `OBSERVABILITY_ERROR` — every observation attempt is auditable. |
| AU-12 (audit generation) | ✅ | The observability surface itself writes audit rows for every call; failures emit structured rows BEFORE responding. |
| SI-7 (software integrity) | ⚠️ | Stream F adds reproducible-build attestation + signed releases |

✅ = covered as of Stream C+G+H+K-foundations. ⚠️ = covered structurally, partial implementation; lands in
Stream E, F, or K.3 per ticket roadmap.

## How to use this scorecard

- **Pre-deployment audit:** read the table above; verify every ✅ row maps to working code
  via the linked references.
- **Quarterly review:** re-grade every dimension. Status changes (e.g. Stream E flips
  Network topology B → A) update the table; the change is tracked in git history.
- **Adding a new control or removing one:** edit this file directly; the `docs/README.md`
  allowlist already covers `SECURITY_SCORECARD.md`. SKS-F01's S-7 rule enforces the
  allowlist match.
