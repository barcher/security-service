# HSM Key Ceremony — KEK + JWT signing key initial setup and rotation

> Document version: 0.1 (2026-05-22)
> Owner: security-service maintainer; ceremony observed by two operators
> Scope: post-Phase-14 HSM-anchored trust model. Covers BOTH the ML-KEM-768 KEK private
>        key (Phase 14 Streams A–F) AND the ES256 JWT signing private key (Stream K).
> Companion docs: `KEK_LIFECYCLE.md` (KEK state machine), `JWT_KEY_LIFECYCLE.md` (signing
>                 key state machine — created in K.0), `TRUST_MODEL.md` (HSM root +
>                 Linkerd identity issuer chain).
> Memory cross-reference: `feedback_hsm_first_trust_model.md` — production trust anchor
>                         lives in a physical HSM via PKCS#11. Cloud KMS (Vault PKI, AWS KMS,
>                         GCP, Azure) is the explicit alternative path, never the default.

---

## 0. Why this exists

The security service holds two distinct classes of long-lived private cryptographic
material:

1. **The ML-KEM-768 KEK private key.** Wraps every DEK in the system. Stored as
   `wrapped_dek_bytes` in `security_keys.deks` after Phase 14 cutover; unwrapped only
   in-process during a `/v1/dek/unwrap` call.

2. **The ES256 JWT signing private key.** Mints every access token in the system. Stored
   as KEK-wrapped `wrapped_private_key_bytes` in `security_keys.jwt_signing_keys` after
   Stream K cutover; unwrapped only in-process during a `/v1/jwt/sign` call.

Both classes are **strategic-direction-relevant secrets** (memory rule
`feedback_hsm_first_trust_model.md`) and both have an HSM-anchored production posture.
This document is the operator runbook for getting them onto an HSM and rotating them
under HSM custody, covering:

- **Initial setup** — first-time generation, two-person observed ceremony, audit-row
  emission, JWKS publication (for JWT) and DEK-rewrap path (for KEK).
- **Rotation** — same ceremony with a key-roll, ordered transition through the
  STAGED → ACTIVE → PRIOR → QUIESCED → RETIRED state machine, zero-downtime cutover.
- **Emergency replacement** — compromise-response procedure when a private key must be
  revoked unscheduled. Tighter, faster, lossy on the rejected-tokens side (KEK) or
  rejected-signing side (JWT).
- **Disposal** — secure deletion of retired key material from the HSM, with audit-chain
  attestation.

The same ceremony pattern applies to both key classes because they share the same
threat model (long-lived high-privilege private key inside the security service) and
the same trust anchor (HSM root → Linkerd identity issuer → operator workstation cert).
**Where the procedures differ, the difference is called out explicitly with **(KEK)**
and **(JWT)** tags.**

---

## 1. Prerequisites

### 1.1 Physical HSM provisioning

The default HSM is **YubiHSM 2** (per memory rule `feedback_hsm_first_trust_model.md`;
cloud-KMS alternative path documented but never automated). Required state before any
ceremony begins:

1. **HSM physically present at the ceremony location.** Two operators witness. The
   `yubihsm-shell` binary version is recorded with `yubihsm-shell --version` and pinned
   in the ceremony log.
2. **Auth keys provisioned.** At minimum: an `admin` key (used for all key-management
   operations during the ceremony; locked away after) and one `signer-<name>` key per
   operator participating. Use the `add authkey` command with a long passphrase generated
   from `openssl rand -base64 24`.
3. **No domain overlap with prior ceremonies.** Each ceremony uses a fresh HSM "domain"
   (the YubiHSM concept that scopes a set of keys; default domain 1 for KEK, domain 2
   for JWT signing key). Mixing domains across ceremonies is forbidden and is the
   single most common operator footgun.
4. **HSM firmware version recorded.** `yubihsm-shell -- "get device info"` output goes
   in the ceremony log.

### 1.2 Audit-chain prerequisites

Before the ceremony begins, the security service must be reachable from the operator
workstation over mTLS and the `audit_events` HMAC chain must verify cleanly. Two-person
gate: one operator runs

```
curl --cacert dev-ca/ca.pem --cert <op-cert.pem> --key <op-key.pem> \
     https://security.local/v1/admin/audit-verify
```

and the response must be `{"chainOk":true,"firstId":...,"lastId":...,"verifiedAt":...}`.
A failure here halts the ceremony — a broken chain means the new key's emission row will
not be attestable. Resolution path: run the `AuditChainRebuildJob` (operator-driven; not
automated) before retrying.

### 1.3 mTLS subject DNs

Two operators must hold valid operator certificates from the HSM-rooted operator CA
(distinct from the operational service certs, distinct from the dashboard-observer cert,
distinct from the operator-decrypt cert — see Phase 14 four-lane model). Subject DN
format: `CN=workautomations-admin-<email-hash>,O=WorkAutomations`. The certs are
short-lived (24 h); each operator mints theirs from the HSM at the start of the
ceremony.

---

## 2. KEK initial setup

The initial KEK is the first ML-KEM-768 keypair the security service operates under.
Today this is provisioned by `security-service-cli generate-kek` reading
`ML_KEM_PUBLIC_KEY` + `ML_KEM_PRIVATE_KEY` env vars — i.e. the private key starts on
disk and the operator manually places it in a secret store. **The HSM-ready path
replaces the env-var step with HSM custody from generation onward.**

### 2.1 Generate the keypair on the HSM

The ML-KEM-768 keypair is generated inside the HSM if the HSM supports the algorithm
(YubiHSM 2 firmware 2.4+ supports post-quantum KEM via the PKCS#11 module). If the HSM
firmware predates ML-KEM support, the fallback path is:

1. Generate on an air-gapped machine using `security-service-cli generate-kek --output
   /secure/path/kek.pem`.
2. Wrap the private bytes immediately using the HSM-resident AES-256 wrapping key (set
   up in §1.1 step 2 with `add wrap-key`):

   ```
   yubihsm-shell -- "put opaque 0 <handle> kek-private-wrapped" < kek.pem
   ```

3. Delete the plaintext PEM from the air-gapped machine
   (`shred -u -n 7 /secure/path/kek.pem`).

The on-HSM path is preferred; the fallback path is documented for older HSM firmware.

### 2.2 Two-person attestation

Both operators witness the generation and sign the ceremony log entry, which includes:

- HSM serial number and firmware version
- Algorithm identifier (`ml-kem-768`)
- Public-key SHA-256 fingerprint (operator-readable; will become the KEK's
  `fingerprint_hex` column value)
- Generation timestamp (`Clock.System.now()` at the security-service host)
- Both operators' mTLS subject DNs
- `ceremony_id` UUID (also recorded as a `KEK_GENERATED` audit row's `detail_json`)

### 2.3 Register the new KEK in the database

The security-service-cli command runs against the production DB over mTLS:

```
security-service-cli kek register \
    --hsm-handle <opaque-id> \
    --public-key-spki <hex> \
    --algorithm ml-kem-768 \
    --status STAGED \
    --ceremony-id <uuid>
```

This inserts a row into `security_keys.keks` with `status=STAGED`. The DEK service
cannot yet use it. **At this point no plaintext private key exists outside the HSM.**

### 2.4 Activate the new KEK

After validation (per §5 "Validation gates"), the operator runs:

```
security-service-cli kek activate --kek-id <uuid>
```

Atomically transitions `STAGED → ACTIVE` and previous `ACTIVE → PRIOR`. New
`/v1/dek/generate` calls immediately mint DEKs wrapped under the new KEK. Existing DEK
rows continue to unwrap under the PRIOR KEK until they are rewrapped by the
`DekRewrapJob`. Emits `KEK_ACTIVATED` audit row.

### 2.5 Rewrap all existing DEKs

The `DekRewrapJob` (Quartz, configurable interval; default off — operator triggers
post-ceremony) walks every row in `security_keys.deks` whose
`wrapped_under_kek_id != active_kek_id` and rewraps them in batches. Progress is
visible in the dashboard observer surface (`/v1/observability/keks` returns
`pendingRewrapCount`). Job completion emits `KEK_REWRAP_COMPLETE` audit row.

---

## 3. JWT signing-key initial setup

The JWT signing private key is the ES256 P-256 key that mints every access JWT.
**The ceremony is structurally identical to §2 for the KEK**, with three differences:

1. **Algorithm:** ES256 / P-256 instead of ML-KEM-768. ES256 is supported natively by
   YubiHSM 2 firmware 2.0+ (no fallback path needed for any currently shipping HSM).
2. **Wrapping:** the private bytes are KEK-wrapped (via the existing
   `CryptoKeyServicePort.wrap` path) before storage in `jwt_signing_keys`. The KEK
   itself lives on the HSM (§2). The wrap is a two-step operation: HSM-generate ES256
   private bytes → HSM-extract under an AES wrap → store the wrapped blob in the DB.
   The plaintext ES256 private bytes never touch disk outside the HSM.
3. **Publication:** the public key (SPKI) is published in `/v1/jwks` immediately on
   `STAGED → ACTIVE`. JWKS consumers (monolith, future financial-service) pick it up
   on next cache refresh (≤ 1 h; lazy refresh on `kid` cache-miss is immediate). No
   rewrap step — JWT tokens are short-lived (15 min default), so the prior key
   naturally falls out of use within `expirationSeconds + clock-skew` after activation.

### 3.1 Generate the keypair on the HSM

```
yubihsm-shell -- "generate asymmetric 0 <handle> jwt-signing ecp256 \
    sign-ecdsa,exportable-under-wrap"
```

The `exportable-under-wrap` capability is critical — the security service needs the
private bytes to be retrievable (under an AES wrap) so they can be stored
KEK-wrapped in the DB and unwrapped in-process at sign time. The plaintext bytes never
leave the HSM unwrapped.

### 3.2 Extract under HSM AES wrap, then re-wrap under KEK

Two-step extraction:

```
# Step 1: HSM-wrap the private key under the HSM's AES wrapping key
yubihsm-shell -- "get wrapped 0 <wrap-key-id> asymmetric-key <handle>" > /tmp/hsm-wrapped.bin

# Step 2: Decrypt the HSM wrap on the security-service host, immediately re-wrap under KEK
security-service-cli jwt-keys register \
    --hsm-wrapped /tmp/hsm-wrapped.bin \
    --hsm-wrap-key-id <wrap-key-id> \
    --status STAGED \
    --ceremony-id <uuid>

# Step 3: Securely delete the HSM-wrapped intermediate
shred -u -n 7 /tmp/hsm-wrapped.bin
```

Step 2 runs inside the security-service-cli process with the plaintext private bytes
held in memory for the duration of the KEK wrap (~ms). The wrap output is then
persisted to `jwt_signing_keys.wrapped_private_key_bytes`. The cli zeroes the
in-memory plaintext after the wrap completes (`ByteArray.fill(0)` in `finally`).

### 3.3 Activate

```
security-service-cli jwt-keys activate --kid <kid>
```

Same atomic transition as KEK activation. The new public key appears in `/v1/jwks` on
the next consumer refresh (≤ 1 h; lazy fetch immediate).

### 3.4 Verify end-to-end

The operator runs a synthetic `/v1/jwt/sign` against the security service with the
operator cert, fetches `/v1/jwks`, and verifies the returned signature locally with
`openssl dgst -verify`. The synthetic request is recorded as a `JWT_SIGNED` audit row.

---

## 4. Rotation (scheduled)

Scheduled rotation runs on the same ceremony procedure as initial setup, with one
additional step: the operator runs the rotation under a fixed plan that minimises the
window where two valid keys exist.

### 4.1 KEK rotation cadence

Default: **operator-driven, not automated.** Recommended cadence: quarterly for KEK
(every ML-KEM-768 keypair generated, ceremony §2 repeated). Each rotation moves the
previous ACTIVE KEK to PRIOR, the previous PRIOR to RETIRED after
`KEK_PRIOR_RETAIN_DAYS` (default 30) once `DekRewrapJob` has rewrapped every DEK under
the new ACTIVE.

### 4.2 JWT signing-key rotation cadence

Default: **operator-driven, not automated for K.0** (per proposal §13.1 open-question
decision OQ-3). Recommended cadence: every 30 days post-K.3 (operator runs the §3
ceremony). The state machine handles the cutover safely:

| Phase | ACTIVE | PRIOR | QUIESCED | Notes |
|---|---|---|---|---|
| t=0 (rotation) | k_new | k_old | (none) | k_new ACTIVE, k_old PRIOR. JWKS publishes both. |
| t=0..15min | k_new | k_old | (none) | New sign requests mint under k_new. Old tokens (issued before t=0) still verify under k_old. |
| t=15min..72h | k_new | k_old (quiesced) | k_old (in transition) | After `JWT_PRIOR_QUIESCE_HOURS=48`, no audit rows reference k_old → marked QUIESCED. |
| t=72h..96h | k_new | (none) | k_old | After `JWT_PRIOR_RETIRE_HOURS=24` post-quiesce, removed from JWKS; future tokens with this `kid` rejected. |
| t=96h+ | k_new | (none) | (none) | k_old → RETIRED; eligible for deletion after `JWT_RETIRED_RETAIN_DAYS=30`. |

This is the `JwtSigningKeyPriorTtlJob` from K.0 ticket SKS-K16.

### 4.3 Both classes — consistency rules

- **Never two ACTIVE rows simultaneously.** Enforced by a generated column + unique
  index on the table (`keks` and `jwt_signing_keys` both have this).
- **STAGED before ACTIVE always.** No direct insert of an ACTIVE row.
- **Ceremony log entries for both classes append-only to `security-service/docs/CEREMONY_LOG.md`** (created on first ceremony; not in the
  repo today). Each entry references the audit-event `id` so log + audit are
  cross-attestable.

---

## 5. Validation gates

Before any STAGED → ACTIVE transition, the operator must validate the new key against
the live security-service host. This catches HSM-extraction-corruption, AAD-mismatch
bugs in the KEK wrap path, and ES256-signature-format issues at the JWS encoder.

### 5.1 KEK validation

1. Generate a probe DEK under the STAGED KEK:
   `security-service-cli kek probe-wrap --kek-id <new-kek-id>`
   Output: a `WrappedDek` envelope and a 32-byte plaintext probe.
2. Round-trip unwrap:
   `security-service-cli kek probe-unwrap --kek-id <new-kek-id> --wrapped <envelope-b64>`
   Output: bytes must equal step 1's plaintext probe.
3. AAD tamper test: modify one byte of `wrapped_dek_bytes`, retry step 2 — must fail
   with AEAD-tag-mismatch.

All three steps pass = proceed to activate. Any failure = halt ceremony, do not activate.

### 5.2 JWT signing-key validation

1. Sign a probe token: `security-service-cli jwt-keys probe-sign --kid <new-kid>
   --audience workautomations-probe`.
   Output: a JWS compact serialization, three base64url segments separated by `.`.
2. Verify against the public key: `security-service-cli jwt-keys probe-verify
   --kid <new-kid> --token <token>` — must succeed.
3. Algorithm-confusion test: take the token from step 1, swap the alg header to
   `none`, retry step 2 — must fail with `algorithm_not_allowed`.

All three pass = activate.

---

## 6. Emergency replacement (compromise response)

When a KEK or JWT signing private key is suspected compromised, the ceremony skips the
gentle PRIOR transition and forces an immediate revocation. **The cost: any tokens or
DEK references still on the old key become unusable.** For JWT this means active users
are signed out (re-login required). For KEK this means any background job that hasn't
yet re-fetched the DEK (which is rare given the in-process cache) must restart.

### 6.1 KEK emergency replacement

1. Run the §2 ceremony to create a new STAGED KEK.
2. Activate immediately (`security-service-cli kek activate --kek-id <new>`).
3. **Force-rewrap every DEK synchronously** rather than via the background job:
   `security-service-cli dek force-rewrap-all --new-kek-id <new>`
4. Mark the old KEK as REVOKED (not RETIRED) with the compromise audit event:
   `security-service-cli kek revoke --kek-id <old> --reason "<incident-id>"`
5. Validate that `/v1/observability/keks` shows the old KEK as REVOKED and no DEKs
   reference it.
6. File a post-incident report including the ceremony_id, the affected DEK IDs, and
   the rewrap duration.

### 6.2 JWT signing-key emergency replacement

1. Run the §3 ceremony to create a new STAGED JWT signing key.
2. Activate immediately.
3. **Force-remove the old `kid` from JWKS:**
   `security-service-cli jwt-keys force-remove --kid <old>`
4. The next JWKS poll by every consumer (≤ 1 h, immediate on cache-miss) drops the
   old public key. Any in-flight token with the old `kid` returns 401 next time it
   verifies.
5. Mark the old key as REVOKED:
   `security-service-cli jwt-keys revoke --kid <old> --reason "<incident-id>"`
6. **Force user re-login:** the monolith has a `forceLogoutAllAfter` config (operator-
   driven; default unset) that, when set to a wall-clock timestamp, causes all tokens
   issued before that time to fail verification. Set this to the compromise
   timestamp; the next visit forces re-login. (This is monolith infrastructure, not a
   security-service concern — documented here for incident-response completeness.)

---

## 7. Disposal — secure deletion from HSM

After the retention window (`KEK_RETIRED_RETAIN_DAYS`, `JWT_RETIRED_RETAIN_DAYS` —
both default 30 days), the operator deletes the private material from the HSM. This
is irreversible.

### 7.1 KEK disposal

1. Confirm no DEK references the KEK in `security_keys.deks`
   (`/v1/observability/keks` → `referencedDekCount=0`).
2. Confirm no audit row references the KEK in the past `KEK_RETIRED_RETAIN_DAYS`
   window.
3. Delete:
   ```
   yubihsm-shell -- "delete 0 <handle>"
   ```
4. Update the DB row: `security-service-cli kek mark-disposed --kek-id <kek-id>`.
5. Emit `KEK_DISPOSED` audit row.

### 7.2 JWT signing-key disposal

Same steps as §7.1 substituting `jwt-keys` for `kek` and `JwksKey` for `Kek`. The
JWKS endpoint already excludes RETIRED keys; this final step removes the private
side from the HSM, completing the lifecycle.

---

## 8. Audit-chain emissions

Every step of every ceremony emits one or more audit rows into `security_keys.audit_events`. The chain is HMAC-SHA-512 row-linked; an
external observer can attest any subset by re-running the chain hash from the row's
`prev_hmac`. Ceremony-related event types:

| Event type | When emitted |
|---|---|
| `KEK_GENERATED` | §2.2 — new KEK row inserted with STAGED |
| `KEK_ACTIVATED` | §2.4 — STAGED → ACTIVE transition |
| `KEK_PROBE_WRAP_OK` / `KEK_PROBE_WRAP_FAIL` | §5.1 validation step results |
| `KEK_REWRAP_COMPLETE` | §2.5 — background or force-rewrap job done |
| `KEK_REVOKED` / `KEK_DISPOSED` | §6.1 / §7.1 |
| `JWKS_KEY_GENERATED` | §3.2 — new `jwt_signing_keys` row inserted |
| `JWKS_KEY_ACTIVATED` | §3.3 |
| `JWT_SIGNED` | §3.4 / §5.2 — probe sign |
| `JWKS_KEY_REVOKED` / `JWKS_KEY_DISPOSED` | §6.2 / §7.2 |

Cross-reference: `AUDIT_LOG.md` documents the HMAC chain mechanism; `SECURITY_SCORECARD.md` lists the FedRAMP control crosswalk for each event.

---

## 9. Cloud-KMS alternative path (non-default)

If a deployment cannot use a physical HSM (e.g. fully-cloud-hosted with no operator
hardware in-cluster), the cloud-KMS alternative path applies:

- **AWS KMS:** the KEK is a KMS-managed AES-256 key; ML-KEM-768 is not natively
  supported, so the KEK material itself is wrapped by KMS's AES envelope encryption
  (`kms:Encrypt` / `kms:Decrypt`). The JWT signing key uses KMS's ECDSA signing API
  (`kms:Sign` with `SigningAlgorithm=ECDSA_SHA_256`) — the private key never leaves
  KMS.
- **GCP KMS / Azure Key Vault:** analogous structure. ECDSA signing API exposed
  directly; ML-KEM-768 wrapped under a KMS-managed key.
- **HashiCorp Vault PKI:** alternative for environments that prefer a software root.
  Same envelope-encryption pattern.

The non-default cloud-KMS paths are not yet implemented; the security-service has no
cloud-KMS adapter. This document records the strategic direction so a future ticket
can implement the alternative without surprising design choices. Per memory rule
`feedback_hsm_first_trust_model.md`, the HSM-anchored path remains the default; any
cloud-KMS adoption requires explicit operator sign-off and a separate ticket.

---

## 10. Sign-off checklist (per ceremony)

The operator runs this checklist for every ceremony — initial setup, scheduled
rotation, or emergency replacement — and pastes the completed list into the
`CEREMONY_LOG.md` entry.

- [ ] Two operators present and identified.
- [ ] HSM firmware version recorded.
- [ ] `ceremony_id` UUID generated.
- [ ] mTLS operator certs valid (24-h expiry confirmed for both operators).
- [ ] Audit-chain verify call passed (`chainOk=true`).
- [ ] Key generated on HSM (or extracted-and-wrapped via §2.1 fallback for older
      firmware).
- [ ] Validation gates passed (§5).
- [ ] STAGED row registered in DB.
- [ ] Activation completed (atomic transition logged).
- [ ] Post-activation health check passed (§5 round-trip, both operators witnessed).
- [ ] Audit rows present and chain re-verifies clean.
- [ ] (Rotation only) prior key transitioned to PRIOR, rewrap/quiesce scheduling
      confirmed.
- [ ] (Disposal only) HSM `delete` command logged.
- [ ] Ceremony log entry appended to `CEREMONY_LOG.md`.
