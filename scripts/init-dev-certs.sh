#!/usr/bin/env bash
# init-dev-certs.sh — Dev-only mTLS material generator for the security service.
#
# Generates (idempotently — re-running is safe; existing files are NOT overwritten unless
# you pass --force):
#
#   security-service/secrets/
#     ├── ca.key                CA private key  (security-service IS the trust authority in dev)
#     ├── ca.pem                CA public cert
#     ├── server.key            server private key (ECDSA P-384)
#     ├── server.pem            server cert, signed by ca
#     ├── keystore.p12          PKCS12 of (server.pem, server.key) — Ktor server-side TLS
#     ├── truststore.p12        PKCS12 of (ca.pem) — JKS-style trust for inbound client certs
#     └── audit_hmac_key        64 raw bytes for AUDIT_HMAC_KEY (newline-stripped base64)
#
# AND — when --export-monolith-client-to <dir> is given — copies:
#
#   <dir>/
#     ├── monolith-client.pem   the monolith's client cert, signed by ca (PKCS#8 key)
#     ├── monolith-client.key   PKCS#8 private key (un-encrypted)
#     └── ca.pem                COPY of CA public cert — the monolith's trust anchor
#
# The CA private key (security-service/secrets/ca.key) is NEVER copied outside this
# service's own directory. The CA public cert (ca.pem) is the only piece other services
# ever see.
#
# Production note: this script is dev-only. In production the CA lives in Linkerd's
# identity issuer (signed by an offline trust anchor in HSM/Vault/KMS); the security
# service receives its server cert via the Linkerd sidecar and never holds CA keys.
# See `meta-project/test_plans/multi_service_smoke_test.md` for the dev usage flow.

set -euo pipefail

# ── Validation helpers ─────────────────────────────────────────────
# Guards against the silent-failure mode where a raw-EC (SEC1) key lands at a
# path that downstream code parses as PKCS#8. The SSL builder fails at the
# first HTTP request rather than at config-load, with no clear error — see
# meta-project conversation 2026-05-19 for the original incident.

assert_regular_file() {
    local path="$1" kind="$2"
    if [[ -L "$path" ]]; then
        echo "FATAL: $kind path '$path' is a symlink — expected a regular file." >&2; exit 1
    fi
    if [[ -d "$path" ]]; then
        echo "FATAL: $kind path '$path' is a DIRECTORY — expected a regular file." >&2
        echo "       This usually means an earlier 'cp -f file dir/' wrote INTO this" >&2
        echo "       directory instead of overwriting it. Remove the directory and re-run." >&2
        exit 1
    fi
    if [[ ! -f "$path" ]]; then
        echo "FATAL: $kind path '$path' is missing or not a regular file." >&2; exit 1
    fi
    if [[ ! -s "$path" ]]; then
        echo "FATAL: $kind path '$path' is empty." >&2; exit 1
    fi
}

assert_pkcs8_key() {
    local path="$1"
    assert_regular_file "$path" "private key"
    local first_line; first_line="$(head -n1 "$path")"
    case "$first_line" in
        "-----BEGIN PRIVATE KEY-----") : ;;  # unencrypted PKCS#8 — OK
        "-----BEGIN ENCRYPTED PRIVATE KEY-----")
            echo "FATAL: '$path' is an ENCRYPTED PKCS#8 key — code expects unencrypted PKCS#8." >&2; exit 1 ;;
        "-----BEGIN EC PRIVATE KEY-----")
            echo "FATAL: '$path' is a raw EC (SEC1) private key — code expects PKCS#8." >&2
            echo "       Convert: openssl pkcs8 -topk8 -nocrypt -in <raw-ec.key> -out <pkcs8.key>" >&2
            exit 1 ;;
        "-----BEGIN RSA PRIVATE KEY-----")
            echo "FATAL: '$path' is a PKCS#1 RSA private key — code expects PKCS#8." >&2
            echo "       Convert: openssl pkcs8 -topk8 -nocrypt -in <pkcs1.key> -out <pkcs8.key>" >&2
            exit 1 ;;
        *)
            echo "FATAL: '$path' first line is '$first_line'." >&2
            echo "       Expected '-----BEGIN PRIVATE KEY-----' (unencrypted PKCS#8)." >&2
            exit 1 ;;
    esac
    if ! openssl pkey -in "$path" -noout >/dev/null 2>&1; then
        echo "FATAL: '$path' is not parseable by openssl (corrupt PKCS#8?)." >&2; exit 1
    fi
}

assert_x509_cert() {
    local path="$1"
    assert_regular_file "$path" "certificate"
    if ! head -n1 "$path" | grep -q '^-----BEGIN CERTIFICATE-----$'; then
        echo "FATAL: '$path' first line is not '-----BEGIN CERTIFICATE-----'." >&2; exit 1
    fi
    if ! openssl x509 -in "$path" -noout >/dev/null 2>&1; then
        echo "FATAL: '$path' is not a parseable X.509 certificate." >&2; exit 1
    fi
}

assert_cert_key_pair() {
    local cert="$1" key="$2"
    local cert_hash key_hash
    cert_hash="$(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null \
        | openssl pkey -pubin -outform DER 2>/dev/null \
        | openssl dgst -sha256 2>/dev/null | awk '{print $2}')"
    key_hash="$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null \
        | openssl dgst -sha256 2>/dev/null | awk '{print $2}')"
    if [[ -z "$cert_hash" || -z "$key_hash" || "$cert_hash" != "$key_hash" ]]; then
        echo "FATAL: cert/key public-key mismatch:" >&2
        echo "       cert='$cert' pub=${cert_hash:-<unreadable>}" >&2
        echo "       key='$key'  pub=${key_hash:-<unreadable>}" >&2
        exit 1
    fi
}

verify_export_triple() {
    # verify_export_triple <cert-path> <pkcs8-key-path> <ca-path>
    assert_x509_cert "$1"
    assert_pkcs8_key "$2"
    assert_x509_cert "$3"
    assert_cert_key_pair "$1" "$2"
}

# ── Locate the security-service root regardless of where the script is invoked from ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SECRETS_DIR="$SECURITY_ROOT/secrets"

# ── Parse args ──
EXPORT_TO=""
EXPORT_FINANCIAL_TO=""
FORCE=0
KEYSTORE_PASSWORD="${SECURITY_SERVICE_KEYSTORE_PASSWORD:-devpass}"

usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") [--export-monolith-client-to <dir>] [--force]

  --export-monolith-client-to <dir>
      After generating CA + server cert, also issue a monolith client cert and copy
      the three files the monolith needs (monolith-client.pem, monolith-client.key,
      ca.pem) into <dir>. Typically <dir> = ../scaffold/secrets.

      Omit this flag to generate the CA + server cert only (run once per CA reset, then
      issue client certs as a separate operator step).

  --export-financial-client-to <dir>
      Issue a client cert for the financial-service to authenticate against THIS
      security service. Files exported: financial-to-security-client.pem,
      financial-to-security-client.key (PKCS#8), security-service-ca.pem. Typically
      <dir> = ../financial-service/secrets.

  --force
      Overwrite existing files. WITHOUT --force, existing files are kept and the script
      exits 0 (idempotent re-run is safe).

Environment overrides:
  SECURITY_SERVICE_KEYSTORE_PASSWORD   default: devpass

Output: $SECRETS_DIR/
EOF
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --export-monolith-client-to)
            [[ $# -lt 2 ]] && { echo "error: --export-monolith-client-to requires a path" >&2; exit 2; }
            EXPORT_TO="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
            shift 2
            ;;
        --export-financial-client-to)
            [[ $# -lt 2 ]] && { echo "error: --export-financial-client-to requires a path" >&2; exit 2; }
            EXPORT_FINANCIAL_TO="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
            shift 2
            ;;
        --force)
            FORCE=1
            shift
            ;;
        -h|--help)
            usage 0
            ;;
        *)
            echo "error: unknown arg '$1'" >&2
            usage 2
            ;;
    esac
done

mkdir -p "$SECRETS_DIR"
cd "$SECRETS_DIR"

# ── Helper: skip if exists unless --force ──
need() {
    local f="$1"
    if [[ -e "$f" && $FORCE -eq 0 ]]; then
        echo "  • $f already exists — skipping (pass --force to overwrite)"
        return 1
    fi
    return 0
}

echo "==> Generating dev mTLS material into: $SECRETS_DIR"

# ── Step 1: CA (ECDSA P-384, 10-year dev validity) ──
if need ca.key; then
    openssl ecparam -name secp384r1 -genkey -noout -out ca.key
    echo "  ✓ ca.key"
fi
if need ca.pem; then
    openssl req -x509 -new -key ca.key -sha384 -days 3650 \
        -subj "/CN=WorkAutomations Dev CA/O=WorkAutomations/L=Local" \
        -out ca.pem 2>/dev/null
    assert_x509_cert ca.pem
    echo "  ✓ ca.pem"
fi

# ── Step 2: Server cert for security-app ──
if need server.key; then
    openssl ecparam -name secp384r1 -genkey -noout -out server.key
    echo "  ✓ server.key"
fi
if need server.pem; then
    openssl req -new -key server.key -sha384 \
        -subj "/CN=security-app/O=WorkAutomations/L=Local" \
        -out server.csr 2>/dev/null
    cat > server.cnf <<'EOF'
subjectAltName = DNS:security-app, DNS:localhost, IP:127.0.0.1
EOF
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
        -days 365 -sha384 -extfile server.cnf -out server.pem 2>/dev/null
    rm -f server.csr server.cnf
    assert_x509_cert server.pem
    assert_cert_key_pair server.pem server.key
    echo "  ✓ server.pem"
fi
if need keystore.p12; then
    openssl pkcs12 -export -inkey server.key -in server.pem -certfile ca.pem \
        -name security-service -password "pass:$KEYSTORE_PASSWORD" -out keystore.p12
    echo "  ✓ keystore.p12 (alias=security-service, password=$KEYSTORE_PASSWORD)"
fi

# ── Step 3: Truststore (CA cert) ──
# keytool -import APPENDS to an existing keystore (unlike openssl which overwrites).
# Remove any existing truststore so the import is reproducible under --force.
if need truststore.p12; then
    rm -f truststore.p12
    keytool -import -trustcacerts -noprompt -file ca.pem -alias dev-ca \
        -keystore truststore.p12 -storetype PKCS12 -storepass "$KEYSTORE_PASSWORD" 2>/dev/null
    echo "  ✓ truststore.p12 (password=$KEYSTORE_PASSWORD)"
fi

# ── Step 4: Audit HMAC key (64 raw bytes, base64) ──
if need audit_hmac_key; then
    openssl rand -base64 64 | tr -d '\n' > audit_hmac_key
    echo "  ✓ audit_hmac_key"
fi

# ── Step 5 (optional): Issue + export monolith client cert ──
if [[ -n "$EXPORT_TO" ]]; then
    echo "==> Issuing monolith client cert + exporting to: $EXPORT_TO"

    # Generate the client cert IN the security service's own secrets dir first; never
    # let CA key material touch the destination.
    if need monolith-client.key; then
        openssl ecparam -name secp384r1 -genkey -noout -out monolith-client.key
        echo "  ✓ monolith-client.key (raw EC)"
    fi
    if need monolith-client.pem; then
        openssl req -new -key monolith-client.key -sha384 \
            -subj "/CN=monolith/O=WorkAutomations/L=Local" \
            -out monolith-client.csr 2>/dev/null
        openssl x509 -req -in monolith-client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
            -days 365 -sha384 -out monolith-client.pem 2>/dev/null
        rm -f monolith-client.csr
        assert_x509_cert monolith-client.pem
        echo "  ✓ monolith-client.pem"
    fi
    # Convert client key to PKCS#8 (required by Bouncy Castle PEM parser on the monolith side)
    if [[ ! -f monolith-client-pkcs8.key || $FORCE -eq 1 ]]; then
        openssl pkcs8 -topk8 -nocrypt -in monolith-client.key -out monolith-client-pkcs8.key
        assert_pkcs8_key monolith-client-pkcs8.key
        echo "  ✓ monolith-client-pkcs8.key (PKCS#8)"
    fi

    # Export step — copy ONLY the three files the monolith needs.
    mkdir -p "$EXPORT_TO"
    for dst in monolith-client.pem monolith-client.key ca.pem; do
        if [[ -d "$EXPORT_TO/$dst" ]]; then
            echo "FATAL: '$EXPORT_TO/$dst' is a directory — remove it before re-running." >&2
            exit 1
        fi
    done
    cp -f monolith-client.pem "$EXPORT_TO/monolith-client.pem"
    cp -f monolith-client-pkcs8.key "$EXPORT_TO/monolith-client.key"
    cp -f ca.pem "$EXPORT_TO/ca.pem"
    verify_export_triple \
        "$EXPORT_TO/monolith-client.pem" \
        "$EXPORT_TO/monolith-client.key" \
        "$EXPORT_TO/ca.pem"
    echo "  ✓ exported + verified: monolith-client.pem, monolith-client.key, ca.pem → $EXPORT_TO"
fi

# ── Step 6 (optional): Issue + export financial-service client cert ──
if [[ -n "$EXPORT_FINANCIAL_TO" ]]; then
    echo "==> Issuing financial→security client cert + exporting to: $EXPORT_FINANCIAL_TO"

    if need financial-to-security-client.key; then
        openssl ecparam -name secp384r1 -genkey -noout -out financial-to-security-client.key
        echo "  ✓ financial-to-security-client.key (raw EC)"
    fi
    if need financial-to-security-client.pem; then
        openssl req -new -key financial-to-security-client.key -sha384 \
            -subj "/CN=financial-app/O=WorkAutomations/L=Local" \
            -out financial-to-security-client.csr 2>/dev/null
        openssl x509 -req -in financial-to-security-client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
            -days 365 -sha384 -out financial-to-security-client.pem 2>/dev/null
        rm -f financial-to-security-client.csr
        assert_x509_cert financial-to-security-client.pem
        echo "  ✓ financial-to-security-client.pem"
    fi
    if [[ ! -f financial-to-security-client-pkcs8.key || $FORCE -eq 1 ]]; then
        openssl pkcs8 -topk8 -nocrypt \
            -in financial-to-security-client.key \
            -out financial-to-security-client-pkcs8.key
        assert_pkcs8_key financial-to-security-client-pkcs8.key
        echo "  ✓ financial-to-security-client-pkcs8.key (PKCS#8)"
    fi

    mkdir -p "$EXPORT_FINANCIAL_TO"
    for dst in financial-to-security-client.pem financial-to-security-client.key security-service-ca.pem; do
        if [[ -d "$EXPORT_FINANCIAL_TO/$dst" ]]; then
            echo "FATAL: '$EXPORT_FINANCIAL_TO/$dst' is a directory — remove it before re-running." >&2
            exit 1
        fi
    done
    cp -f financial-to-security-client.pem "$EXPORT_FINANCIAL_TO/financial-to-security-client.pem"
    cp -f financial-to-security-client-pkcs8.key "$EXPORT_FINANCIAL_TO/financial-to-security-client.key"
    cp -f ca.pem "$EXPORT_FINANCIAL_TO/security-service-ca.pem"
    verify_export_triple \
        "$EXPORT_FINANCIAL_TO/financial-to-security-client.pem" \
        "$EXPORT_FINANCIAL_TO/financial-to-security-client.key" \
        "$EXPORT_FINANCIAL_TO/security-service-ca.pem"
    echo "  ✓ exported + verified: financial-to-security-client.{pem,key}, security-service-ca.pem → $EXPORT_FINANCIAL_TO"
fi

echo ""
echo "Done."
echo ""
echo "Security-service .env paths (relative to security-service/):"
echo "  SECURITY_SERVICE_KEYSTORE_PATH=./secrets/keystore.p12"
echo "  SECURITY_SERVICE_KEYSTORE_PASSWORD=$KEYSTORE_PASSWORD"
echo "  SECURITY_SERVICE_KEYSTORE_ALIAS=security-service"
echo "  SECURITY_SERVICE_TRUSTSTORE_PATH=./secrets/truststore.p12"
echo "  SECURITY_SERVICE_TRUSTSTORE_PASSWORD=$KEYSTORE_PASSWORD"
echo "  AUDIT_HMAC_KEY=\$(cat ./secrets/audit_hmac_key)    # or paste the literal value"
echo ""
if [[ -n "$EXPORT_TO" ]]; then
    echo "Monolith .env paths (relative to scaffold/):"
    echo "  SECURITY_SERVICE_URL=https://localhost:8443"
    echo "  SECURITY_SERVICE_CLIENT_CERT_PATH=./secrets/monolith-client.pem"
    echo "  SECURITY_SERVICE_CLIENT_KEY_PATH=./secrets/monolith-client.key"
    echo "  SECURITY_SERVICE_CA_PATH=./secrets/ca.pem"
fi
