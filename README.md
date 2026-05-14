# security-service

Standalone post-quantum key-management service for the Work Automations platform.

This service owns ML-KEM-768 KEK material; wraps and unwraps DEKs on behalf of the monolith
(and any future sibling services) over mTLS; runs the KEK lifecycle (STAGED → ACTIVE →
PRIOR → RETIRED); and emits an HMAC-SHA-512-chained audit log of every cryptographic
operation. The monolith never holds KEK material after Phase 14 cutover.

See [`scaffold/docs/proposals/shared_key_service.md`](../scaffold/docs/proposals/shared_key_service.md)
for the full Phase 14 design and the rationale for splitting key management into its own
process. Ticket-level decomposition lives in
[`meta-project/work-items/phases/phase14/items.md`](../meta-project/work-items/phases/phase14/items.md).

## Stream status

| Stream | Status | Lands |
|--------|--------|-------|
| **A** — Skeleton + crypto core (`SKS-A01..A06`) | ✅ complete | Gradle layout, ML-KEM service, HKDF-SHA-512 wrap, KekProviderPort, CryptoKeyServicePort byte-identical to monolith copy |
| **B** — HTTP API + mTLS (`SKS-B01..B06`) | ✅ complete | `/v1/health`, `/v1/dek/{generate,wrap,unwrap,rewrap}`, `/v1/admin/{rotate-kek,key-status}`, mTLS auth + audit + per-subject rate limit |
| **C** — DB schema + Quartz jobs + audit chain (`SKS-C01..C10`) | ✅ complete | own MySQL (env-gated), Flyway V1–V3, persistent audit log with HMAC-SHA-512 row chain, 6 Quartz jobs + scheduler, Stream-C docs |
| **D** — Monolith integration (`SKS-D01..D05`) | ✅ complete | `RemoteCryptoKeyServiceAdapter`, `LocalDevCryptoKeyServiceAdapter`, mode-aware DI resolver, HOCON + `docs/API_KEYS.md` |
| **E** — Cutover (`SKS-E01..E06`) | ✅ complete | docker-compose stack (security profile, named networks, docker secrets), security-service Dockerfile, V4 legacy DEK provenance, `import-monolith-deks` CLI, V111 + `LegacyEnvelopeRewriteJob` use case + 5 tests, DEPLOYMENT.md cutover §6, CERT_GENERATION.md OpenSSL recipes. **SKS-D04 / SKS-E05** (deletion of in-process crypto + repos) deferred to the operator's post-cutover dwell step. |
| **F** — Docs + ArchUnit + eval (`SKS-F01..F04`) | planned | S-1..S-9 boundary tests, cross-repo port byte-identity check (S-9) |

## What works right now (end of Stream B)

- `./gradlew build` — all 7 modules compile, lint, and pass 58 unit tests.
- `./gradlew :infrastructure:run` — starts Ktor on `:8443` (plaintext for now); `GET /v1/health`
  returns 200. **Every other endpoint returns 401** because the default
  `PeerCertChainExtractor` binding is `DenyAllPeerCertChainExtractor` — Stream E swaps in
  the real Netty/sidecar-header extractor.
- The 4 crypto routes + 2 admin routes are **wired in code** and exercised by 18 unit
  tests but not yet mounted in `Application.kt`. That last wiring step lands at the start
  of Stream E so the routes appear in production traffic only once the mTLS path is real.

## Repository layout

```
security-service/
├── application/                       — ports, use cases, value types (no framework deps)
│   └── src/main/kotlin/.../application/
│       ├── ports/                     — CryptoKeyServicePort, KekProviderPort, AuditLogPort,
│       │                                AdminAllowList
│       └── usecases/                  — GenerateDek, WrapDek, UnwrapDek, RewrapDek,
│                                        GenerateNewKekPair, GetKeyStatus
├── domain/                            — pure domain types (currently empty; Stream C populates)
├── adapters/
│   ├── inbound/
│   │   ├── http/                      — Ktor routes, mTLS plugin, rate limiter, DTOs
│   │   └── scheduler/                 — Quartz jobs (Stream C populates)
│   └── outbound/
│       ├── crypto/                    — ML-KEM service + HKDF-SHA-512 wrap (the only module
│       │                                allowed to import BouncyCastle MLKEMxxx classes)
│       └── persistence/               — Exposed repositories (Stream C populates)
├── infrastructure/                    — composition root: Application.kt + SecurityServiceModule
│   └── src/main/kotlin/.../infrastructure/
│       ├── audit/                     — Slf4jAuditLogAdapter (Stream-B fallback)
│       ├── config/                    — RateLimitConfig (env-var loader)
│       ├── di/                        — Koin module
│       ├── kek/                       — FileMountKekProvider
│       └── tls/                       — MtlsConfig (PKCS12 keystore loader)
└── docs/                              — see docs/README.md
```

**Architectural rules (enforced by ArchUnit in Stream F):**

- Adapter modules MUST NOT depend on each other. Cross-adapter coordination flows through
  application-layer ports only.
- The crypto adapter is the ONLY module allowed to import `org.bouncycastle.pqc.crypto.mlkem.*`.
- The application module MUST NOT depend on any adapter module.
- `application/ports/CryptoKeyServicePort.kt` MUST be byte-identical to the monolith copy
  at `scaffold/application/src/main/kotlin/.../application/ports/CryptoKeyServicePort.kt`
  modulo the package declaration. Enforced by rule **S-9**.

## Quickstart (local dev)

```bash
# 1. Configure
cp .env.example .env
# (.env is gitignored; the committed defaults are safe for `./gradlew :infrastructure:run`)

# 2. Build + test
./gradlew build

# 3. Run
./gradlew :infrastructure:run
# Listening on http://0.0.0.0:8443 (plaintext; Stream E adds TLS)
# GET /v1/health → 200
# Everything else → 401 mtls_required (deny-all extractor)
```

To exercise the crypto routes locally before Stream E lands, run the unit test suites —
they install a [`TestPeerCertChainExtractor`](adapters/inbound/http/src/test/kotlin/com/workautomations/security/adapters/inbound/http/auth/PeerCertChainExtractor.kt)
that injects a synthetic ECDSA P-384 client cert into call attributes, bypassing the need
for a real TLS handshake:

```bash
./gradlew :adapters:inbound:http:test
```

## HTTP route surface

| Method + Path | Auth | Purpose | Source |
|---------------|------|---------|--------|
| `GET /v1/health` | none | Liveness probe | `HealthRoute.kt` |
| `POST /v1/dek/generate` | mTLS | Generate a fresh DEK; return wrapped + plaintext | `CryptoRoutes.kt` |
| `POST /v1/dek/wrap` | mTLS | Wrap externally-provided 32-byte DEK | `CryptoRoutes.kt` |
| `POST /v1/dek/unwrap` | mTLS, rate-limited | Unwrap a stored DEK | `CryptoRoutes.kt` |
| `POST /v1/dek/rewrap` | mTLS | Re-wrap DEK under a new KEK pub key | `CryptoRoutes.kt` |
| `POST /v1/admin/rotate-kek` | mTLS + admin | Generate next ML-KEM keypair | `AdminRoutes.kt` |
| `GET /v1/admin/key-status` | mTLS + admin | Active KEK fingerprint + availability | `AdminRoutes.kt` |

Every authenticated route propagates the caller's mTLS subject DN into every audit event
written via `AuditLogPort`. Until Stream C, audit events go to SLF4J INFO; from Stream C
onward they go to `security_keys.audit_events` with an HMAC-SHA-512 row chain.

## Configuration

All configuration is sourced from environment variables (typically backed by a k8s
ConfigMap or docker-compose `environment` block). See [`.env.example`](.env.example) for the
full list and per-variable documentation.

Topic-specific docs:

- [`docs/MTLS.md`](docs/MTLS.md) — mTLS contract, cert generation, deny-all default, what Stream E adds
- [`docs/RATE_LIMITING.md`](docs/RATE_LIMITING.md) — per-subject token bucket on `/v1/dek/unwrap`, env-var contract, scale-out caveats

## Testing

```bash
./gradlew test                                    # 58 tests across 9 classes
./gradlew :adapters:outbound:crypto:test          # crypto round-trip + boundary tests
./gradlew :adapters:inbound:http:test             # routes + mTLS auth + rate limiter
./gradlew :infrastructure:test                    # KEK provider + rate-limit config
```

Eval shortcut covering ktlint + detekt + tests + build:

```bash
./gradlew ktlintCheck detekt test build
```

## Why a separate repository, not a `:security-service` Gradle module inside `scaffold/`

Section 2 of the Phase 14 proposal answers this directly: the security service has its own
deployable lifecycle, its own database, its own Hikari pool, its own Quartz scheduler, its
own audit chain, and a different blast-radius from the monolith. Co-locating it as a
sibling Gradle module would inherit the monolith's release cadence, classpath, and DI
graph — none of which are appropriate for a key-management service that needs to be
isolatable, separately auditable, and FIPS/FedRAMP-attestable on its own merits. See
proposal §2 "Decision: Option B" and §3 "Service topology" for the full reasoning.
