# Cert generation for the security service

> **Authoritative architecture:** [TRUST_MODEL.md](TRUST_MODEL.md) — read it first if you
> want to understand *why* the layout is shaped the way it is. This doc is the *how* —
> the exact commands to run in dev. Production cert provisioning is HSM-rooted via
> Linkerd; see TRUST_MODEL.md §3 + §6.
>
> The cryptographic profile is **ECDSA P-384 (secp384r1)** per proposal §7.2. RSA / EC
> P-256 keys are NOT accepted by the server's TLS engine — every recipe below uses P-384.

## The fastest path — run the script

```bash
# From security-service/
./scripts/init-dev-certs.sh --export-monolith-client-to ../scaffold/secrets
```

That's it. The script is idempotent (re-running is a no-op for existing files; pass
`--force` to overwrite). It performs every step documented below: CA + server cert +
truststore + monolith client cert + audit HMAC key, and copies the three monolith-facing
files (`monolith-client.pem`, `monolith-client.key`, `ca.pem`) into `scaffold/secrets/`.

The rest of this doc is the manual recipe — useful for reviewing what the script does,
for non-standard layouts, or for issuing additional client certs (e.g. operator admin
workstation cert).

## File layout (own-secrets — each service holds only what it consumes)

Per [TRUST_MODEL.md §2.1](TRUST_MODEL.md), each service has its own `secrets/` dir; no
service reads from another's tree at runtime.

```
security-service/secrets/             # gitignored; security-service reads from here
├── ca.key                            # CA private key — NEVER copied outside this dir
├── ca.pem                            # CA public cert
├── server.key
├── server.pem
├── keystore.p12                      # PKCS12 — server cert + key, alias=security-service
├── truststore.p12                    # PKCS12 — CA cert (for client-cert validation)
├── audit_hmac_key                    # base64 64-byte HMAC-SHA-512 key
├── ml_kem_public_key                 # base64 ML-KEM-768 public key (~1580 chars)
└── ml_kem_private_key                # base64 ML-KEM-768 private key (~3204 chars)

scaffold/secrets/                     # gitignored; monolith reads from here
├── monolith-client.pem               # COPY exported from security-service
├── monolith-client.key               # COPY (PKCS#8) exported from security-service
└── ca.pem                            # COPY of CA public cert — the monolith's trust anchor
```

**Invariants:**
- `ca.key` (CA private) never leaves `security-service/secrets/`.
- Only `ca.pem` (CA public) is exported to consuming services.
- The monolith's `.env` references only paths inside `scaffold/secrets/`; no `../security-service/...`.

## Step 1 — generate the CA

```bash
mkdir -p security-service/secrets
cd security-service/secrets

# CA private key (ECDSA P-384)
openssl ecparam -name secp384r1 -genkey -noout -out ca.key

# Self-signed CA cert, 10-year validity for dev
openssl req -x509 -new -key ca.key -sha384 -days 3650 \
    -subj "/CN=WorkAutomations Dev CA/O=WorkAutomations/L=Local" \
    -out ca.pem
```

## Step 2 — server cert for `security-app`

```bash
# Server private key
openssl ecparam -name secp384r1 -genkey -noout -out server.key

# CSR
openssl req -new -key server.key -sha384 \
    -subj "/CN=security-app/O=WorkAutomations/L=Local" \
    -out server.csr

# SAN config — server-app must be reachable as `security-app` inside compose and
# `localhost` for ad-hoc curl probes from the host.
cat > server.cnf <<'EOF'
subjectAltName = DNS:security-app, DNS:localhost, IP:127.0.0.1
EOF

# Sign with the CA
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 365 -sha384 -extfile server.cnf -out server.pem

# PKCS12 keystore — alias must match SECURITY_SERVICE_KEYSTORE_ALIAS (default `security-service`)
openssl pkcs12 -export -inkey server.key -in server.pem -certfile ca.pem \
    -name security-service -password pass:devpass -out keystore.p12
```

## Step 3 — truststore for `security-app`

The truststore holds the CA cert; the server's TLS engine uses it to validate inbound
client certs.

```bash
keytool -import -trustcacerts -noprompt -file ca.pem -alias dev-ca \
    -keystore truststore.p12 -storetype PKCS12 -storepass devpass
```

## Step 4 — monolith client cert (generated here, exported to scaffold)

Generate inside `security-service/secrets/`, then copy the three monolith-facing files to
`scaffold/secrets/`. The CA private key NEVER leaves this directory.

```bash
# Still in security-service/secrets/
openssl ecparam -name secp384r1 -genkey -noout -out monolith-client.key

openssl req -new -key monolith-client.key -sha384 \
    -subj "/CN=monolith,O=WorkAutomations,L=Local" \
    -out monolith-client.csr

openssl x509 -req -in monolith-client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 365 -sha384 -out monolith-client.pem

# PKCS#8 — the monolith's RemoteCryptoKeyServiceSslContext rejects encrypted PEM, and the
# BC PEMParser path needs PKCS#8, not OpenSSL's legacy EC PRIVATE KEY format.
openssl pkcs8 -topk8 -nocrypt -in monolith-client.key -out monolith-client-pkcs8.key
mv monolith-client-pkcs8.key monolith-client.key

# Export the three monolith-facing files. The CA private key (ca.key) is NOT exported.
mkdir -p ../../scaffold/secrets
cp monolith-client.pem ../../scaffold/secrets/monolith-client.pem
cp monolith-client.key ../../scaffold/secrets/monolith-client.key
cp ca.pem               ../../scaffold/secrets/ca.pem
```

Wire into `scaffold/.env`:

```env
SECURITY_SERVICE_URL=https://localhost:8443
SECURITY_SERVICE_CLIENT_CERT_PATH=./secrets/monolith-client.pem
SECURITY_SERVICE_CLIENT_KEY_PATH=./secrets/monolith-client.key
SECURITY_SERVICE_CA_PATH=./secrets/ca.pem
```

The monolith's [`RemoteCryptoKeyServiceSslContext`](../../scaffold/adapters/outbound/crypto/src/main/kotlin/com/workautomations/adapters/outbound/crypto/RemoteCryptoKeyServiceSslContext.kt)
loads these directly at startup.

## Step 5 — admin client cert (operator workstation)

A separate client cert lets an operator hit `/v1/admin/*` endpoints from their laptop.
Same recipe; the subject DN must be added to `SECURITY_ADMIN_SUBJECTS` on `security-app`.

```bash
openssl ecparam -name secp384r1 -genkey -noout -out admin-client.key
openssl req -new -key admin-client.key -sha384 \
    -subj "/CN=admin-1,O=WorkAutomations,L=Local" \
    -out admin-client.csr
openssl x509 -req -in admin-client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 365 -sha384 -out admin-client.pem
openssl pkcs8 -topk8 -nocrypt -in admin-client.key -out admin-client-pkcs8.key
mv admin-client-pkcs8.key admin-client.key
```

Then on `security-app`:

```env
SECURITY_ADMIN_SUBJECTS=CN=admin-1,O=WorkAutomations,L=Local
```

(RFC 2253 DN form; semicolon-separated when multiple admin DNs are configured.)

## Step 6 — ML-KEM keypair + audit HMAC key

The KEK is ML-KEM-768. Use the `generate-kek` bootstrap CLI — it mints a fresh
keypair, prints both halves as KEY=VALUE lines to stdout (ready to paste into `.env`),
and the SHA-256 fingerprint of the public key to stderr (record this out-of-band for
later attestation against `GET /v1/admin/key-status`):

```bash
# From security-service/. Captures stdout to a file; stderr stays on the terminal
# so the operator sees the fingerprint + safety banner.
./gradlew :infrastructure:run --args="generate-kek" > /tmp/kek.env

# Or against the built jar (no Gradle daemon dependency):
java -jar infrastructure/build/libs/infrastructure-all.jar generate-kek > /tmp/kek.env
```

**Bootstrap only.** The CLI refuses to run when `ML_KEM_PUBLIC_KEY_CURRENT` is already
set in the environment; once a current KEK exists, in-band rotations go through
`POST /v1/admin/rotate-kek` (mTLS + admin allowlist + audit chain) — see
[`KEK_LIFECYCLE.md`](KEK_LIFECYCLE.md#bootstrap-vs-rotation). For genuine disaster
recovery (no surviving current-KEK material), pass `--force` to override the gate.

Paste the two KEY=VALUE lines from `/tmp/kek.env` into `security-service/.env` (or
install the private key under the file-mount / HSM, depending on environment).

```bash
# ML-KEM-768 keypair (alternative: discrete file-mount form for HSM-adjacent deployments)
echo -n '<base64 public key>'  > ml_kem_public_key
echo -n '<base64 private key>' > ml_kem_private_key

# HMAC-SHA-512 audit key — 64 bytes of randomness, base64-encoded, no trailing newline
openssl rand -base64 64 | tr -d '\n' > audit_hmac_key
```

`scripts/init-dev-certs.sh` does the audit HMAC step automatically; the ML-KEM keypair
remains a manual step until the CLI lands.

## Production note

This doc is dev-only. In prod, the trust anchor is HSM-rooted via PKCS#11 and the
in-cluster issuer is provisioned through Linkerd. The `keystore.p12` / `truststore.p12`
files become irrelevant because the application layer doesn't terminate TLS — Linkerd
does it at the sidecar. The KEK is HSM-wrapped before persistence; the security service
unwraps it via PKCS#11 at boot. Full prod runbook lives in
[TRUST_MODEL.md §6](TRUST_MODEL.md).

`init-dev-certs.sh` MUST NOT be run in production — it generates a self-signed CA on
disk, which is a development convenience and an audit finding in production.
