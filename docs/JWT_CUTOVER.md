# JWT cutover — monolith HS256 to security-service ES256

Stream K migration plan. K.0 ships the security-service surface (this doc lives next
to it); K.1 + K.2 + K.3 execute the consumer-side change in the monolith. This doc is
the operator playbook for the cutover window.

## 1. Phases at a glance

| Phase | What changes | Reversibility | Where the JWT signing material lives |
|---|---|---|---|
| **Pre-K.0** | None — monolith mints HS256 with `JWT_SECRET` env var. | n/a | Monolith `.env` |
| **K.0 (this stream)** | Security service exposes `POST /v1/jwt/sign` + `GET /v1/jwks`. Monolith is unchanged. | n/a — monolith still signs locally | Both: security-service has new ES256 key; monolith still has HS256 secret |
| **K.1** | Monolith adds a JWKS-cache + ES256 verify path to the shared-security-client. Monolith STILL mints HS256 itself. | Trivial — toggle a feature flag | Both |
| **K.2** | Monolith switches its mint path to call `POST /v1/jwt/sign`. Both algorithms still accepted on verify. | Feature flag — flip back to local HS256 mint | Both; security-service is authoritative source for new tokens |
| **K.3** | Monolith deletes `Algorithm.HMAC256`, deletes `JWT_SECRET` env var, deletes the local mint path. ArchUnit rule M-10 ratchets to `emptySet()`. | One-way after `JWT_SECRET` is rotated out of secret stores | Security service only |

Each phase has its own sign-off gate; this doc covers the operator runbook for K.2 and
K.3 specifically.

## 2. Pre-flight checklist (run before K.2)

- [ ] An ACTIVE ES256 signing key exists in the security service:
      `./security-service jwt-keys generate-pair --activate --operator-email=ops@...`
- [ ] `GET /v1/jwks` returns a one-key set with the expected `kid`.
- [ ] Monolith health probe of the new security-service `/v1/jwt/sign` endpoint passes
      (mTLS + audience allow-list both green). See [`JWT_OPERATIONS.md`](JWT_OPERATIONS.md) §1.5
      for error catalog if it fails.
- [ ] Monolith's `SECURITY_JWT_AUDIENCE_ALLOWLIST` entry exists on the security-service
      side for the monolith's subject DN + `workautomations-api` audience.
- [ ] Grafana panel `jwt_verify_algorithm_total{algorithm=<...>}` is wired and showing
      `HS256` traffic. This panel becomes the K.3 cutover gate.
- [ ] Refresh-token cleanup job is enabled in the monolith
      (`RefreshTokenCleanupJob`, K-amend-6) — verifies the 64-byte upgrade is settled.

## 3. K.2 execution (HS256 → ES256 mint flip)

1. **Roll the flag.** Set `MONOLITH_JWT_MINT_SOURCE=security-service` in the monolith
   environment. `RefreshTokenUseCase` and `LoginUseCase` switch to calling
   `SecurityServiceJwtClient.sign(...)` instead of the local `JwtTokenService.mint(...)`
   path.
2. **Watch the dashboards.** Within 5 minutes the `jwt_signed_total{source="security-service"}`
   counter should be the dominant series; the `jwt_signed_total{source="local-hs256"}`
   counter should drop to zero (no new locally-minted tokens).
3. **Verify with a real login.** End-to-end test: log out, log in, observe the
   resulting access token decodes as ES256 with the expected `kid`. The shared-client
   JWKS cache should have already populated from `GET /v1/jwks`.
4. **Burn-in period — 24 h.** Existing HS256 tokens remain valid for their full TTL
   (≤ 24 h per the route cap). The shared-client verify path accepts both `alg` values
   during this window.
5. **Rollback gate.** Within the burn-in window the rollback is a single flag flip:
   `MONOLITH_JWT_MINT_SOURCE=local`. Tokens minted during the K.2 window remain valid
   (they were issued by security-service and signed under ES256; the JWKS cache verifies
   them with no special handling).

## 4. K.3 execution (HS256 verify deletion)

Only proceed after the burn-in window AND the Grafana gate:

> Grafana panel `jwt_verify_algorithm_total{algorithm="HS256"}` MUST be flat at 0 for
> ≥ 24 consecutive hours.

When the gate is green:

1. **Code change.** Delete `Algorithm.HMAC256(...)`, the `JWT_SECRET` env var read, and
   the `HS256` branch of the verify path in the monolith. Update the ArchUnit
   `STREAM_K_LEGACY_EXEMPTIONS` set to `emptySet()`. Update `SECURITY_SCORECARD.md`'s
   IA-5 row from ⚠️ to ✅ in the SAME commit per the scorecard upkeep rule.
2. **Secret rotation.** Remove `JWT_SECRET` from k8s secrets, `.env.example`, and any
   docs that reference it. The secret is now dead weight; leaving it in any vault is a
   minor risk and a major audit-question.
3. **Deploy.** Rolling restart. The monolith no longer accepts HS256 tokens; any old
   token still in flight returns 401 `algorithm_not_allowed` on its next request.
4. **Confirm.** `jwt_verify_algorithm_total{algorithm="HS256"}` remains at 0 (now
   structurally — the code path is gone).

## 5. What does NOT change in K.2/K.3

* **Refresh tokens stay in the monolith.** The security service never sees refresh
  tokens. `RefreshTokenUseCase` continues to verify the refresh-token hash locally,
  then calls `/v1/jwt/sign` to mint a new access JWT. Cross-ref:
  [Shared Key Service rule 17 in CLAUDE.md].
* **The 64-byte refresh-token width.** K-amend-6 (deployed in K.0 prep) is independent
  of K.2/K.3.
* **The dashboard observer mTLS lane (Stream L).** Separate cert chain, separate
  allow-list; not touched by K cutover.
* **The operator decrypt CLI lane (Stream M).** Same — independent and not affected.

## 6. Failure modes the operator should expect

| Symptom | Likely cause | Recovery |
|---|---|---|
| Monolith logs `audience_forbidden` 403s after K.2 flip | `SECURITY_JWT_AUDIENCE_ALLOWLIST` missing the monolith's subject DN + `workautomations-api` | Update env var on security-service, restart, retry |
| Monolith logs `unknown_kid` on verify | JWKS cache stale + key was rotated since | Eager refresh (already automatic on `kid` miss); if it persists, security-service `/v1/jwks` is unreachable — investigate mTLS / network |
| `JWKS_HEALTH_CHECK_FAILED` audit rows post-rotation | Newly-ACTIVE key wasn't wrapped under the current KEK (e.g. KEK rotated mid-ceremony) | Re-run `jwt-keys generate-pair --activate` to mint a fresh key under the current KEK; investigate why the ceremony's KEK assumption broke |
| Grafana HS256 gate never reaches zero | Long-TTL tokens issued before K.2 still in circulation; OR a non-test caller is still using a stashed HS256 token | Wait the full TTL; if still nonzero, audit-log inspection for `JWT_VERIFY_OK` rows with `algorithm=HS256` |

## 7. Cross-references

* HTTP surface: [`JWT_OPERATIONS.md`](JWT_OPERATIONS.md).
* Lifecycle + Quartz jobs: [`JWT_KEY_LIFECYCLE.md`](JWT_KEY_LIFECYCLE.md).
* Operator key ceremony: [`HSM_KEY_CEREMONY.md`](HSM_KEY_CEREMONY.md).
* Scorecard upkeep rule (must update SECURITY_SCORECARD.md in K.3 commit):
  `meta-project/CLAUDE.md` "Security scorecard upkeep rule".
