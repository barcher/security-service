# security-service docs

Topic-specific documentation for the security service. This directory is intentionally
flat — no subfolders — and constrained to a fixed allowlist of filenames. The allowlist is
enforced in Stream F by ArchUnit rule **S-7**: any file added here that is not in the
allowlist fails CI.

## Allowlist (canonical)

| File | Status | Owner stream | Purpose |
|------|--------|--------------|---------|
| `README.md` | ✅ this file | — | Index of allowed files + ownership. |
| `MTLS.md` | ✅ written | Stream B → E | mTLS contract, cert generation, `PeerCertChainExtractor` evolution. |
| `RATE_LIMITING.md` | ✅ written | Stream B → C | Per-subject token bucket on `/v1/dek/unwrap`, env-var contract, scale-out caveats. |
| `AUDIT_LOG.md` | ✅ written | Stream C | HMAC-SHA-512 row-chain schema + verification protocol from proposal §10. |
| `KEK_LIFECYCLE.md` | ✅ written | Stream C | STAGED → ACTIVE → PRIOR → RETIRED state machine + rotation sequence from proposal §8. |
| `MIGRATIONS.md` | ✅ written | Stream C | Flyway migration index for the security service's own MySQL. |
| `SECURITY_SCORECARD.md` | ✅ written | Re-graded each stream | Operator-facing posture snapshot: TLS profile, key isolation, audit chain, rate limiting, FedRAMP control crosswalk. |
| `DEPLOYMENT.md` | ✅ written | Stream E | docker-compose stack, k3s topology (§3.3, §3.4), secrets layout. |
| `CERT_GENERATION.md` | ✅ written | Stream E | OpenSSL recipes for the PKCS12 server + client keystores (ECDSA P-384). |
| `TRUST_MODEL.md` | ✅ written | Stream E follow-up | Self-contained architecture doc: three trust authorities (workload mTLS, ingress, KEK), why security-service IS the dev CA, prod replacement via Linkerd + HSM-backed offline trust anchor. |
| `HSM_KEY_CEREMONY.md` | ✅ written | Stream K (2026-05-22) | Operator runbook for KEK + JWT signing-key initial setup, scheduled rotation, emergency replacement, and disposal. HSM-anchored (YubiHSM 2 default); cloud-KMS alternative path documented but non-default. |
| `JWT_OPERATIONS.md` | ✅ written | Stream K K.0 | HTTP reference for `POST /v1/jwt/sign` + `GET /v1/jwks`. Two-gate caller-auth contract (mTLS + audience allow-list), JWS header format, error catalog, `SECURITY_JWT_AUDIENCE_ALLOWLIST` env-var schema. |
| `JWT_KEY_LIFECYCLE.md` | ✅ written | Stream K K.0 | State machine + Quartz job catalog for `jwt_signing_keys`. Singleton-ACTIVE invariant, PRIOR/QUIESCED grace windows, default TTLs + retention rationale, operator CLI invocations. |
| `JWT_CUTOVER.md` | ✅ written | Stream K K.2 + K.3 | Operator playbook for monolith HS256 → security-service ES256 migration. Pre-flight checklist, phase-by-phase rollout, Grafana gates for K.3 deletion, failure-mode recovery. |
| `OBSERVABILITY_API.md` | ✅ written | Stream L L.0 | Wire contract for the 5 GETs under `/v1/observability/`, dashboard-observer mTLS allow-list, rate-limit configuration, audit-event semantics, threat-model, sample mTLS curl invocations. |
| `OPERATOR_DECRYPT_RUNBOOK.md` | ✅ written | Stream M M.2 | Operator-facing runbook for the security-service-only operator decrypt CLI (`tools/decrypt-cli/`). Cert minting + allow-list setup, usage by key handle / audit event id, output-format catalog, audit-trail semantics, exit codes, rehearsal flow, troubleshooting. Single-sided per the 2026-05-24 amendment — no monolith-side sibling CLI. |

Anything outside this list belongs in the top-level [`README.md`](../README.md), in
[`.env.example`](../.env.example), or in the source itself as a KDoc block. No
`docs/proposals/`, no `docs/architecture/`, no inline screenshots.
