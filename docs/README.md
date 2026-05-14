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

Anything outside this list belongs in the top-level [`README.md`](../README.md), in
[`.env.example`](../.env.example), or in the source itself as a KDoc block. No
`docs/proposals/`, no `docs/architecture/`, no inline screenshots.
