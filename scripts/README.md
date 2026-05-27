# `security-service/scripts/`

Operator scripts collocated with the security-service. Read this before running anything
here. The companion doc — [`../docs/CERT_GENERATION.md`](../docs/CERT_GENERATION.md) —
mirrors the cert-lane table and the per-lane consumer env-var contract; if the two ever
disagree, treat that as a bug and reconcile in the same commit.

## Scripts

| Script | Purpose | Production? |
|---|---|---|
| [`init-dev-certs.sh`](init-dev-certs.sh) | Mint CA + server cert + per-lane client certs. | **Dev only.** Production uses HSM-rooted Linkerd identity. |
| [`seed-dev-kek-row.sh`](seed-dev-kek-row.sh) | Insert the first `keks` lifecycle row from the env-var KEK at bootstrap. | **Dev only.** Production seeds rows via the documented operator runbook (audit-chain-tracked). |

### `init-dev-certs.sh`

Dev-only mTLS material generator. **Production cert provisioning is HSM-rooted via
Linkerd** ([`../docs/TRUST_MODEL.md`](../docs/TRUST_MODEL.md) §6) — this script must
never run on a production host.

Three things to know before running:

1. **One flag per lane.** The script knows about three client-cert lanes. Each lane has
   one and only one flag. The flag fixes the **subject DN** and the **filenames** — you
   cannot accidentally mint an operational cert into a path the observer adapter reads,
   or vice versa, because the filenames are different and the security-service's
   per-lane allow-lists reject the wrong DN.

2. **Run `--list-lanes` first.** Prints the full table at the terminal — confirm the lane
   you want before exporting.

   ```bash
   ./scripts/init-dev-certs.sh --list-lanes
   ```

3. **Idempotent by default.** Existing files are kept on re-run unless `--force` is
   passed. The CA + server cert are minted once; re-running the script just regenerates
   any missing pieces.

#### Cert-lane table

| Lane                       | Flag                                  | Client cert filename               | Client key filename (PKCS#8)       | `-subj` form                                                  | Consumer env vars                                     |
|----------------------------|---------------------------------------|------------------------------------|------------------------------------|---------------------------------------------------------------|-------------------------------------------------------|
| Operational (monolith)     | `--export-monolith-client-to <dir>`   | `monolith-client.pem`              | `monolith-client.key`              | `/CN=monolith/O=WorkAutomations/L=Local`                      | scaffold: `SECURITY_SERVICE_CLIENT_{CERT,KEY,CA}_PATH` |
| Operational (financial)    | `--export-financial-client-to <dir>`  | `financial-to-security-client.pem` | `financial-to-security-client.key` | `/CN=financial-app/O=WorkAutomations/L=Local`                 | financial: `SECURITY_SERVICE_CLIENT_{CERT,KEY,CA}_PATH` |
| Dashboard observer         | `--export-observer-to <dir>`          | `dashboard-observer.pem`           | `dashboard-observer.key`           | `/CN=workautomations-dashboard-observer/O=WorkAutomations/L=Local` | scaffold: `SECURITY_READONLY_CLIENT_{CERT,KEY,CA}_PATH` |
| Admin (operator)           | `--export-admin-to <dir>`             | `admin-bootstrap-client.pem`       | `admin-bootstrap-client.key`       | `/CN=workautomations-admin-bootstrap/O=WorkAutomations/L=Local`    | operator-only — `curl --cert <pem> --key <key>` for `POST /v1/admin/rotate-kek` |

**JDK render order** (RFC 2253) reverses the `-subj` order. So the security-service's
allow-list env vars must use the reversed form:

- Operational monolith → `L=Local,O=WorkAutomations,CN=monolith`
- Operational financial → `L=Local,O=WorkAutomations,CN=financial-app`
- Dashboard observer → `L=Local,O=WorkAutomations,CN=workautomations-dashboard-observer`
- Admin → `L=Local,O=WorkAutomations,CN=workautomations-admin-bootstrap`

#### Common recipes

```bash
# Standard dev setup — operational lane for the monolith.
./scripts/init-dev-certs.sh --export-monolith-client-to ../scaffold/secrets

# Enable the dashboard observability sub-app. Distinct cert, distinct DN.
./scripts/init-dev-certs.sh --export-observer-to ../scaffold/secrets

# Both at once.
./scripts/init-dev-certs.sh \
  --export-monolith-client-to ../scaffold/secrets \
  --export-observer-to        ../scaffold/secrets

# Operational lane for the financial-service.
./scripts/init-dev-certs.sh --export-financial-client-to ../financial-service/secrets

# Re-issue everything from scratch (rotates the CA — invalidates all existing certs).
./scripts/init-dev-certs.sh --force \
  --export-monolith-client-to ../scaffold/secrets \
  --export-observer-to        ../scaffold/secrets

# Bootstrap the keks table at first install (or after a DB wipe). Mint an admin cert
# then call POST /v1/admin/rotate-kek to insert the first ACTIVE keks row. The cert is
# NOT consumed by any running service — the operator runs curl directly with it.
./scripts/init-dev-certs.sh --export-admin-to ../scaffold/secrets
# Then add the admin DN to security-service/.env:
#   SECURITY_ADMIN_SUBJECTS=L=Local,O=WorkAutomations,CN=workautomations-admin-bootstrap
# Restart security-service. Then:
curl -sS -k \
  --cert  ../scaffold/secrets/admin-bootstrap-client.pem \
  --key   ../scaffold/secrets/admin-bootstrap-client.key \
  --cacert ../scaffold/secrets/ca.pem \
  -X POST https://localhost:8443/v1/admin/rotate-kek
```

#### Why lane isolation matters

A leaked operational cert MUST NOT grant access to `/v1/observability/*` and vice versa.
The script enforces this at three layers:

1. **Distinct subject DNs** (set in this script; the script is the single source of
   truth — there is no `--subject` flag).
2. **Distinct filenames** (so a `cp` typo can't put an operational key under the observer
   path or vice versa).
3. **Distinct security-service allow-lists** (`SECURITY_OPERATIONAL_CLIENT_SUBJECTS` for
   operational lanes, `SECURITY_DASHBOARD_OBSERVER_SUBJECTS` for the observer). Adding
   a new lane = updating this script AND the matching allow-list env var in the same PR.

Trust-model background: [`../docs/TRUST_MODEL.md`](../docs/TRUST_MODEL.md) §4.
Observability lane DN contract: [`../docs/OBSERVABILITY_API.md`](../docs/OBSERVABILITY_API.md).
Cert-format invariants (PKCS#8, never raw EC): [`../docs/MTLS.md`](../docs/MTLS.md).

### `seed-dev-kek-row.sh`

One-shot bootstrap helper: reads `ML_KEM_PUBLIC_KEY_CURRENT` from
`security-service/.env`, computes the SHA-256 colon-hex fingerprint that the `keks`
table expects, and inserts a single ACTIVE row.

```bash
./scripts/seed-dev-kek-row.sh
```

**When to run:** exactly once, after first install (or after a DB wipe), before
`./gradlew :infrastructure:run --args="jwt-keys generate-pair --activate"`. The
`KekEnvelopeAdapter.wrap()` path that JWT signing key creation depends on requires an
ACTIVE row in the `keks` table; without one you get `IllegalStateException("No ACTIVE
KEK; cannot wrap")`. After bootstrap, in-band rotation always goes through
`POST /v1/admin/rotate-kek` + operator SQL — never this script.

Idempotent — re-running is a no-op when a row with the same fingerprint already exists.
Production runs the equivalent SQL by hand via the documented operator runbook so that
every keks row is created by a real rotation event (and recorded in the audit chain),
never by a developer script.

#### Safety guards baked in

Verified at the bottom of every export:

- **PKCS#8 contract** — raw EC / PKCS#1 keys are rejected with a clear error pointing at
  the `openssl pkcs8 -topk8` conversion. Raw EC fails silently inside the Ktor Java
  client engine (5-second request timeout, no server-side activity), so the script
  refuses to produce that footgun.
- **Cert/key public-key match** — each exported `.pem` + `.key` pair is checked to share
  the same public key. Prevents a mid-`cp` mix-up from getting committed to scaffold's
  secrets dir.
- **Refuse-to-overwrite-directory** — if the destination path for an exported file is
  somehow a directory (usually because of a previous `cp -f file dir/` typo), the script
  FATALs with the remediation step instead of cp'ing inside it.

If any guard fails, the script exits non-zero and the destination is left in whatever
state it was in before the export — re-run with `--force` once you've cleaned up.
