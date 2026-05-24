# Operator Decrypt CLI — Runbook (Phase 14 Stream M, M.2)

> Status: SHIPPED 2026-05-24 (single-sided per the 2026-05-24 amendment to
> `scaffold/docs/proposals/operator_decrypt_scripts.md`).
> CLI source: `security-service/tools/decrypt-cli/`.
> Distribution: `./gradlew :tools:decrypt-cli:installDist` →
> `tools/decrypt-cli/build/install/decrypt-cli/`.
> Audit-event constant: `OPERATOR_DECRYPT_RUN` in
> `application/.../AuditLogPort.kt::AuditEventType`.

This is the *operator-facing* runbook. The architecture rationale lives in
`scaffold/docs/proposals/operator_decrypt_scripts.md` v0.2; the rules-of-engagement
live in `meta-project/CLAUDE.md` "Shared Key Service" rules 23–28.

---

## 0. When to use this CLI

You are an operator (engineer / IR responder / forensics analyst) and you need
to inspect ciphertext owned by the security service:

- A wrapped DEK from `security_keys.deks` — typically to confirm a row exists
  for a `dek_handle` that the monolith referenced in an error log.
- A wrapped JWT signing private key from `security_keys.jwt_signing_keys` —
  typically to extract the wrapped envelope for offline forensic replay.
- A historical audit event from `security_keys.audit_events` — typically to
  pull the full `detail_json` for a specific `OPERATOR_DECRYPT_RUN`,
  `DEK_UNWRAPPED`, or similar row.

**This CLI does NOT decrypt monolith-owned tables** (`principal_data`,
`financial_*`, every encrypted column in `principal_column_encryption_config`)
directly. Per the single-sided override, there is no monolith-side CLI. If
you need to decrypt a monolith row:

1. Use this CLI to unwrap the DEK by handle (see [§2.1](#21-by-key-handle)).
2. The CLI emits the DEK envelope (kem ciphertext + AES-256-GCM blob). Use
   a small one-off local script with that envelope + the affected row's
   ciphertext to compute the plaintext on your workstation.

This indirection is intentional — every DEK unwrap goes through the
security-service `/v1/dek/unwrap` audit chain via the operator subject DN,
so the forensic trail is complete regardless of where the plaintext lands.

---

## 1. One-time setup

### 1.1 Mint an operator certificate

Operator certs use the locked subject-DN pattern (CLAUDE.md rule 28):

```
CN=workautomations-operator-decrypt-<email-hash>,O=WorkAutomations
```

where `<email-hash>` is the first 16 hex chars of
`SHA-256(operator_email.lowercase().trim())`.

Mint the cert against the HSM-rooted operator CA (production) or the dev CA
(local rehearsal):

```bash
# Production (HSM-resident operator CA):
hsm-operator-ca mint \
  --operator-email ops-alice@example.com \
  --validity 24h \
  --out ~/.operator-decrypt/ops-alice/

# Local rehearsal (dev CA):
security-service/scripts/init-dev-certs.sh \
  --operator-email ops-alice@example.com \
  --out ~/.operator-decrypt-dev/ops-alice/
```

Both flows emit a PKCS#8 unencrypted `.key` + matching `.crt`. Per
`feedback_cert_pem_format_silent_failure.md`, raw EC / PKCS#1 keys fail
silently inside the Ktor Java client engine — always use PKCS#8.

### 1.2 Add your DN to the security-service allow-list

Edit `security-service/.env` (or your deployment's equivalent):

```bash
# Append your DN (semicolon-separated; mirrors SECURITY_ADMIN_SUBJECTS parsing).
SECURITY_OPERATOR_DECRYPT_SUBJECTS=CN=workautomations-operator-decrypt-<your-hash>,O=WorkAutomations
```

This env var is **separate from** `SECURITY_ADMIN_SUBJECTS` (admin write ops)
and `SECURITY_DASHBOARD_OBSERVER_SUBJECTS` (read-only metadata) per CLAUDE.md
rule 28. The three subject-DN lanes are load-bearing for audit filtering and
MUST NOT be collapsed.

Restart `security-app` so the new allow-list is picked up. (Future ticket
may add hot-reload.)

### 1.3 Install the CLI on your workstation

```bash
cd /path/to/workAutomations/security-service
./gradlew :tools:decrypt-cli:installDist
cp -r tools/decrypt-cli/build/install/decrypt-cli/ ~/.local/share/
export PATH=$HOME/.local/share/decrypt-cli/bin:$PATH
decrypt-cli --help   # smoke check
```

**Do NOT commit the installDist output anywhere or bake it into a docker
image.** CLAUDE.md rule 24 — the production `security-app` image MUST NOT
ship the CLI; operators run it from their workstation only.

### 1.4 Source the security-service env

The CLI reads the same env vars the security service uses for its DB pool
and audit-chain HMAC:

```bash
# Pull from your sealed-secrets / 1Password / vault — the values match prod.
export SECURITY_DB_URL="jdbc:mysql://<host>:3306/security_keys?<flags>"
export SECURITY_DB_USER="security_service"
export SECURITY_DB_PASSWORD="<from secret store>"
export AUDIT_HMAC_KEY="<from secret store>"
```

A "rehearsal" workflow with `local-dev` mode is documented at the end of this
runbook (§5).

---

## 2. Usage

### 2.1 By key handle

```bash
decrypt-cli \
  --operator-email ops-alice@example.com \
  --reason "IR-2026-05-24-001 — investigating unwrap-rate spike on kek-3" \
  --key-handle ab12cd34...   # 32-hex DEK handle OR a JWT key id
```

The CLI looks up the handle first in `security_keys.deks`; if no match,
falls back to `security_keys.jwt_signing_keys.kid`. The output JSON has the
table name in `rows[].table`.

### 2.2 By audit event id

```bash
decrypt-cli \
  --operator-email ops-alice@example.com \
  --reason "IR-2026-05-24-001 — pulling full detail_json for audit row 41723" \
  --audit-event-id 41723
```

Returns the audit row's `detail_json` field. Today this is plaintext JSON
(no decryption); the executor exists so a future ticket that encrypts
`detail_json` drops in cleanly.

### 2.3 Output formats

```
--output json    # default — single document with invocation envelope + rows
--output jsonl   # one JSON line per row; invocation envelope goes to stderr
--output csv     # header row + one row per result
```

### 2.4 Writing to disk

```bash
decrypt-cli ... \
  --output-file /tmp/ir-2026-05-24-001.json \
  --i-accept-plaintext-on-disk
```

The `--i-accept-plaintext-on-disk` flag is REQUIRED when `--output-file` is
set (CLAUDE.md rule 27 — plaintext on disk is explicit opt-in). The opt-in
is recorded in the audit row's `detail_json.i_accept_plaintext_on_disk` field.

Delete the file as soon as the investigation completes. The CLI emits a
warning to stderr at run end reminding you.

### 2.5 Dry-run

```bash
decrypt-cli ... --dry-run
```

Validates args, writes the audit row, and emits the invocation envelope with
`row_count: 0` and no rows. No plaintext is materialised. Use this to check
your `--reason` is acceptable and the audit row will look right before
running the real decrypt.

### 2.6 Overriding the hard cap

```bash
decrypt-cli ... --i-understand-large-export
```

Default caps: 10 000 rows OR 24 hours of time-window scope. Above either
threshold, the CLI refuses to run unless you opt in. The opt-in is
recorded in the audit row.

---

## 3. Audit trail

Each invocation writes **exactly one** `OPERATOR_DECRYPT_RUN` row to
`security_keys.audit_events` BEFORE any unwrap call (CLAUDE.md rule 26).
Row contents:

| Column | Value |
|--------|-------|
| `event_type` | `OPERATOR_DECRYPT_RUN` |
| `actor_subject` | `CN=workautomations-operator-decrypt-<hash>,O=WorkAutomations` |
| `success` | `true` (always — failures emit additional rows but the pre-run row stands) |
| `detail_json` | `operator_email`, `reason`, `argument_vector`, `correlation_id`, `row_count` (estimate), `tables`, `output_destination`, `i_understand_large_export`, `i_accept_plaintext_on_disk`, `schema_version="1.0"` |
| `dek_handle` / `kek_id` | NULL — the operation is not bound to a specific key in the row's structural fields; the `argument_vector` carries the references |
| `occurred_at` | `now()` at CLI invocation start |

When the CLI calls `/v1/dek/unwrap` for an actual unwrap, the security
service writes an additional `DEK_UNWRAPPED` row whose `actor_subject` is
also the operator DN — forensics can join the two rows on the DN hash + a
short time window.

---

## 4. Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 64 | usage error (bad args) |
| 65 | hard cap exceeded without `--i-understand-large-export` |
| 70 | software error (DB connection failed, runtime boot exception, etc.) |

---

## 5. Local rehearsal

Before running against prod, rehearse against a docker-compose stack:

```bash
cd security-service
docker compose up -d mysql security-app
./scripts/init-dev-certs.sh --operator-email ops-test@example.com \
  --out ~/.operator-decrypt-dev/

# Source the dev env (the docker-compose-provided creds + dev HMAC key)
source .env.dev

# Append your dev operator DN to the allow-list (one-shot):
docker compose exec security-app sh -c \
  "export SECURITY_OPERATOR_DECRYPT_SUBJECTS=\"CN=workautomations-operator-decrypt-$(echo -n ops-test@example.com | shasum -a 256 | cut -c1-16),O=WorkAutomations\""

decrypt-cli --operator-email ops-test@example.com \
  --reason "rehearsal — smoke test of decrypt-cli against dev stack" \
  --key-handle <pick any from security_keys.deks> \
  --dry-run
```

Confirm:

- Exit code 0.
- `security_keys.audit_events` has exactly one new `OPERATOR_DECRYPT_RUN`
  row with your DN in `actor_subject`.
- Output JSON has `invocation.dry_run: true` and `row_count: 0`.

---

## 6. Operational do's and don'ts

**DO:**

- Always supply a `--reason` that names the incident ticket or investigation
  context. The reason is the load-bearing field for any future audit review.
- Always start with `--dry-run` on prod, then re-run without it once you've
  confirmed the row count + DN look right.
- Always delete `--output-file` plaintext as soon as the investigation is
  closed. The file is operator-owned; it does not appear in any retention
  catalog.

**DO NOT:**

- Do not run the CLI inside a `security-app` docker container via
  `docker compose exec` or `docker exec`. CLAUDE.md rule 24 — the CLI is a
  workstation tool, never a container-resident tool. Even if a future image
  accidentally bundles it, invoking it inside the running service container
  is forbidden.
- Do not pipe CLI output to anything that durably stores plaintext (a
  notebook, a Slack DM, a Jira comment) without `--i-accept-plaintext-on-disk`
  already in the audit row. The opt-in is the operator's record that the
  plaintext left ephemeral memory.
- Do not paste the operator cert subject DN into any other allow-list
  (admin, dashboard observer). The three DN lanes are independent for
  audit-filtering purposes.

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Exit 64 + `--operator-email is required` | Forgot to set the env-var-driven defaults | Pass `--operator-email` explicitly on every run; we deliberately don't read it from env to prevent silent operator-identity drift. |
| Exit 65 + `row count … exceeds the 10000-row hard cap` | Tried to decrypt a too-large set | Tighten the scope (smaller time window, fewer ids) OR pass `--i-understand-large-export` if the large export is genuinely warranted. The opt-in goes into the audit row. |
| Exit 70 + `failed to boot runtime: …` | DB connection failed (env vars missing or wrong) | Re-source the security-service `.env`; verify `SECURITY_DB_URL` resolves, the credential is valid, and the workstation has network reachability to the DB host (you may need a jump-host tunnel). |
| `HttpRequestTimeoutException` after 5 s on a `/v1/dek/unwrap` call | mTLS cert format wrong (raw EC / PKCS#1) | Convert to PKCS#8 with `openssl pkcs8 -topk8 -nocrypt`. Cross-ref: `feedback_cert_pem_format_silent_failure.md`. |
| Cert subject DN doesn't match the locked pattern | Cert minted before SKS-M14 sign-off | Re-mint via `hsm-operator-ca mint` or `init-dev-certs.sh`. The locked pattern is invariant — `CN=workautomations-operator-decrypt-<16-hex>,O=WorkAutomations`. |
