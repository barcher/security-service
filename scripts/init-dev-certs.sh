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
# PLUS — when an --export-* flag is given — issues a per-lane client cert AND copies its
# three-file triple to the destination. There is ONE flag per lane; filenames + subject
# DNs are fixed by the script so an operator cannot pick the wrong cert by accident.
#
# Lanes (one --export-* flag each):
#
#   --export-monolith-client-to <dir>      (operational east-west: monolith → security)
#     ├── monolith-client.pem              CN=monolith,O=WorkAutomations,L=Local
#     ├── monolith-client.key              PKCS#8 (unencrypted)
#     └── ca.pem
#
#   --export-financial-client-to <dir>     (operational east-west: financial → security)
#     ├── financial-to-security-client.pem CN=financial-app,O=WorkAutomations,L=Local
#     ├── financial-to-security-client.key PKCS#8 (unencrypted)
#     └── security-service-ca.pem
#
#   --export-observer-to <dir>             (read-only observability: monolith dashboard)
#     ├── dashboard-observer.pem           CN=workautomations-dashboard-observer,O=WorkAutomations,L=Local
#     ├── dashboard-observer.key           PKCS#8 (unencrypted)
#     └── ca.pem
#
#   --export-admin-to <dir>                (operator KEK bootstrap + rotation cert)
#     ├── admin-bootstrap-client.pem       CN=workautomations-admin-bootstrap,O=WorkAutomations,L=Local
#     ├── admin-bootstrap-client.key       PKCS#8 (unencrypted)
#     └── ca.pem
#     Used by the operator to call POST /v1/admin/rotate-kek (seeds the keks row at
#     bootstrap, drives in-band rotations afterward). NOT consumed by any running service.
#
# Run `init-dev-certs.sh --list-lanes` for the same table at the terminal.
#
# The CA private key (security-service/secrets/ca.key) is NEVER copied outside this
# service's own directory. The CA public cert (ca.pem) is the only piece other services
# ever see.
#
# **Lane isolation is the contract.** Each lane uses a distinct subject DN so the
# security-service's per-lane allow-lists (SECURITY_OPERATIONAL_CLIENT_SUBJECTS,
# SECURITY_DASHBOARD_OBSERVER_SUBJECTS, etc.) can authorize ONE lane without authorizing
# any other. Reusing a single cert across lanes collapses that isolation — see
# docs/TRUST_MODEL.md (§4 lane model), docs/MTLS.md, and docs/OBSERVABILITY_API.md
# (observer lane DN contract).
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
EXPORT_OBSERVER_TO=""
EXPORT_ADMIN_TO=""
FORCE=0
KEYSTORE_PASSWORD="${SECURITY_SERVICE_KEYSTORE_PASSWORD:-devpass}"

# ── Lane registry — single source of truth for filenames + subject DNs. ───────────────
# An operator cannot pick the wrong cert by accident: the lane name selects the flag, the
# flag forces the filename pair + DN. To change a DN, edit it HERE and update the
# allow-list on the security-service side (matching env var) in the same commit.
#
# Format: lane name | client cert filename | DN (CSR -subj form) | consumer env var
LANE_OPERATIONAL_MONOLITH_CERT="monolith-client.pem"
LANE_OPERATIONAL_MONOLITH_KEY="monolith-client.key"
LANE_OPERATIONAL_MONOLITH_DN="/CN=monolith/O=WorkAutomations/L=Local"

LANE_OPERATIONAL_FINANCIAL_CERT="financial-to-security-client.pem"
LANE_OPERATIONAL_FINANCIAL_KEY="financial-to-security-client.key"
LANE_OPERATIONAL_FINANCIAL_DN="/CN=financial-app/O=WorkAutomations/L=Local"

LANE_OBSERVER_CERT="dashboard-observer.pem"
LANE_OBSERVER_KEY="dashboard-observer.key"
LANE_OBSERVER_DN="/CN=workautomations-dashboard-observer/O=WorkAutomations/L=Local"

LANE_ADMIN_CERT="admin-bootstrap-client.pem"
LANE_ADMIN_KEY="admin-bootstrap-client.key"
LANE_ADMIN_DN="/CN=workautomations-admin-bootstrap/O=WorkAutomations/L=Local"

usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") [LANE-FLAG <dir>] ... [--force]
       $(basename "$0") --list-lanes

Generates the CA + server cert in $SECRETS_DIR (always), then optionally issues +
exports a client cert PER LANE. There is exactly one --export-* flag per lane, and the
filename + subject DN for each lane is fixed by this script. The destination directory
ends up with three files: <client-cert>, <client-key (PKCS#8)>, <ca-cert>.

LANE-FLAG options (combine freely; each runs independently):

  --export-monolith-client-to <dir>
      OPERATIONAL lane: monolith → security mTLS for /v1/dek/*, /v1/jwt/sign,
      /v1/admin/*. Files: $LANE_OPERATIONAL_MONOLITH_CERT, $LANE_OPERATIONAL_MONOLITH_KEY, ca.pem.
      DN: $LANE_OPERATIONAL_MONOLITH_DN
      Typical <dir>: ../scaffold/secrets
      Consumer env vars (monolith): SECURITY_SERVICE_CLIENT_{CERT,KEY,CA}_PATH

  --export-financial-client-to <dir>
      OPERATIONAL lane: financial-service → security mTLS for /v1/dek/*. Files:
      $LANE_OPERATIONAL_FINANCIAL_CERT, $LANE_OPERATIONAL_FINANCIAL_KEY, security-service-ca.pem.
      DN: $LANE_OPERATIONAL_FINANCIAL_DN
      Typical <dir>: ../financial-service/secrets
      Consumer env vars (financial): SECURITY_SERVICE_CLIENT_{CERT,KEY,CA}_PATH

  --export-observer-to <dir>
      DASHBOARD OBSERVER lane: monolith → security read-only /v1/observability/*.
      DISTINCT subject DN from the operational lane so the security-service's
      SECURITY_DASHBOARD_OBSERVER_SUBJECTS allow-list can authorize this lane
      independently. Files: $LANE_OBSERVER_CERT, $LANE_OBSERVER_KEY, ca.pem.
      DN: $LANE_OBSERVER_DN
      Typical <dir>: ../scaffold/secrets
      Consumer env vars (monolith): SECURITY_READONLY_CLIENT_{CERT,KEY,CA}_PATH

  --export-admin-to <dir>
      ADMIN lane: operator workstation cert for POST /v1/admin/rotate-kek + GET
      /v1/admin/key-status. Used at bootstrap to seed the keks row, then for in-band
      KEK rotation thereafter. NOT consumed by any running service — the operator runs
      curl with these files directly. Files: $LANE_ADMIN_CERT, $LANE_ADMIN_KEY, ca.pem.
      DN: $LANE_ADMIN_DN
      Typical <dir>: ../scaffold/secrets   (any operator-accessible path works)
      Consumer: operator runs \`curl --cert <pem> --key <key>\`. The security-service
      allow-list env var is SECURITY_ADMIN_SUBJECTS (see KEK_LIFECYCLE.md).

  --list-lanes
      Print the full lane table (above) and exit. No files are written.

  --force
      Overwrite existing files. WITHOUT --force, existing files are kept and the script
      exits 0 (idempotent re-run is safe).

Environment overrides:
  SECURITY_SERVICE_KEYSTORE_PASSWORD   default: devpass

Output: $SECRETS_DIR/
EOF
    exit "${1:-0}"
}

list_lanes() {
    cat <<EOF
Cert lanes managed by this script:

  Lane           | --export flag                    | Client cert filename                  | Client key filename                   | Subject DN (as configured on -subj)
  ---------------+----------------------------------+---------------------------------------+---------------------------------------+------------------------------------
  operational    | --export-monolith-client-to      | $LANE_OPERATIONAL_MONOLITH_CERT             | $LANE_OPERATIONAL_MONOLITH_KEY              | $LANE_OPERATIONAL_MONOLITH_DN
   (monolith)    |                                  |                                       |                                       |
  operational    | --export-financial-client-to     | $LANE_OPERATIONAL_FINANCIAL_CERT | $LANE_OPERATIONAL_FINANCIAL_KEY | $LANE_OPERATIONAL_FINANCIAL_DN
   (financial)   |                                  |                                       |                                       |
  observer       | --export-observer-to             | $LANE_OBSERVER_CERT                   | $LANE_OBSERVER_KEY                    | $LANE_OBSERVER_DN
   (dashboard)   |                                  |                                       |                                       |
  admin          | --export-admin-to                | $LANE_ADMIN_CERT              | $LANE_ADMIN_KEY               | $LANE_ADMIN_DN
   (operator)    |                                  |                                       |                                       |

Subject DN order at runtime (JDK X500Principal.name, RFC 2253) reverses the -subj order
above. For each lane the security-service sees:
  operational monolith    → L=Local,O=WorkAutomations,CN=monolith
  operational financial   → L=Local,O=WorkAutomations,CN=financial-app
  dashboard observer      → L=Local,O=WorkAutomations,CN=workautomations-dashboard-observer
  admin                   → L=Local,O=WorkAutomations,CN=workautomations-admin-bootstrap

Configure the matching allow-list env vars on the security-service in that exact form
(SECURITY_OPERATIONAL_CLIENT_SUBJECTS / SECURITY_DASHBOARD_OBSERVER_SUBJECTS /
SECURITY_ADMIN_SUBJECTS).
EOF
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
        --export-observer-to)
            [[ $# -lt 2 ]] && { echo "error: --export-observer-to requires a path" >&2; exit 2; }
            EXPORT_OBSERVER_TO="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
            shift 2
            ;;
        --export-admin-to)
            [[ $# -lt 2 ]] && { echo "error: --export-admin-to requires a path" >&2; exit 2; }
            EXPORT_ADMIN_TO="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
            shift 2
            ;;
        --list-lanes)
            list_lanes
            exit 0
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

# ── Step 8 (optional): Issue + export admin client cert ──
if [[ -n "$EXPORT_ADMIN_TO" ]]; then
    echo "==> Issuing ADMIN lane cert (DN: $LANE_ADMIN_DN)"
    echo "    Export → $EXPORT_ADMIN_TO"
    echo "    Files  → $LANE_ADMIN_CERT, $LANE_ADMIN_KEY, ca.pem"

    if need admin-bootstrap-client.key; then
        openssl ecparam -name secp384r1 -genkey -noout -out admin-bootstrap-client.key
        echo "  ✓ admin-bootstrap-client.key (raw EC)"
    fi
    if need admin-bootstrap-client.pem; then
        openssl req -new -key admin-bootstrap-client.key -sha384 \
            -subj "$LANE_ADMIN_DN" \
            -out admin-bootstrap-client.csr 2>/dev/null
        openssl x509 -req -in admin-bootstrap-client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
            -days 365 -sha384 -out admin-bootstrap-client.pem 2>/dev/null
        rm -f admin-bootstrap-client.csr
        assert_x509_cert admin-bootstrap-client.pem
        echo "  ✓ admin-bootstrap-client.pem"
    fi
    if [[ ! -f admin-bootstrap-client-pkcs8.key || $FORCE -eq 1 ]]; then
        openssl pkcs8 -topk8 -nocrypt -in admin-bootstrap-client.key -out admin-bootstrap-client-pkcs8.key
        assert_pkcs8_key admin-bootstrap-client-pkcs8.key
        echo "  ✓ admin-bootstrap-client-pkcs8.key (PKCS#8)"
    fi

    mkdir -p "$EXPORT_ADMIN_TO"
    for dst in admin-bootstrap-client.pem admin-bootstrap-client.key ca.pem; do
        if [[ -d "$EXPORT_ADMIN_TO/$dst" ]]; then
            echo "FATAL: '$EXPORT_ADMIN_TO/$dst' is a directory — remove it before re-running." >&2
            exit 1
        fi
    done
    cp -f admin-bootstrap-client.pem        "$EXPORT_ADMIN_TO/admin-bootstrap-client.pem"
    cp -f admin-bootstrap-client-pkcs8.key  "$EXPORT_ADMIN_TO/admin-bootstrap-client.key"
    cp -f ca.pem                            "$EXPORT_ADMIN_TO/ca.pem"
    verify_export_triple \
        "$EXPORT_ADMIN_TO/admin-bootstrap-client.pem" \
        "$EXPORT_ADMIN_TO/admin-bootstrap-client.key" \
        "$EXPORT_ADMIN_TO/ca.pem"
    echo "  ✓ exported + verified: admin-bootstrap-client.pem, admin-bootstrap-client.key, ca.pem → $EXPORT_ADMIN_TO"
fi

# ── Step 7 (optional): Issue + export dashboard-observer client cert ──
if [[ -n "$EXPORT_OBSERVER_TO" ]]; then
    echo "==> Issuing OBSERVER lane cert (DN: $LANE_OBSERVER_DN)"
    echo "    Export → $EXPORT_OBSERVER_TO"
    echo "    Files  → $LANE_OBSERVER_CERT, $LANE_OBSERVER_KEY, ca.pem"

    if need dashboard-observer.key; then
        openssl ecparam -name secp384r1 -genkey -noout -out dashboard-observer.key
        echo "  ✓ dashboard-observer.key (raw EC)"
    fi
    if need dashboard-observer.pem; then
        openssl req -new -key dashboard-observer.key -sha384 \
            -subj "$LANE_OBSERVER_DN" \
            -out dashboard-observer.csr 2>/dev/null
        openssl x509 -req -in dashboard-observer.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
            -days 365 -sha384 -out dashboard-observer.pem 2>/dev/null
        rm -f dashboard-observer.csr
        assert_x509_cert dashboard-observer.pem
        echo "  ✓ dashboard-observer.pem"
    fi
    # PKCS#8 conversion — same contract as the monolith operational lane (feedback in
    # docs/MTLS.md: raw EC fails silently in the Ktor Java client engine after a 5s
    # request timeout with no server-side activity).
    if [[ ! -f dashboard-observer-pkcs8.key || $FORCE -eq 1 ]]; then
        openssl pkcs8 -topk8 -nocrypt -in dashboard-observer.key -out dashboard-observer-pkcs8.key
        assert_pkcs8_key dashboard-observer-pkcs8.key
        echo "  ✓ dashboard-observer-pkcs8.key (PKCS#8)"
    fi

    mkdir -p "$EXPORT_OBSERVER_TO"
    for dst in dashboard-observer.pem dashboard-observer.key ca.pem; do
        if [[ -d "$EXPORT_OBSERVER_TO/$dst" ]]; then
            echo "FATAL: '$EXPORT_OBSERVER_TO/$dst' is a directory — remove it before re-running." >&2
            exit 1
        fi
    done
    cp -f dashboard-observer.pem      "$EXPORT_OBSERVER_TO/dashboard-observer.pem"
    cp -f dashboard-observer-pkcs8.key "$EXPORT_OBSERVER_TO/dashboard-observer.key"
    cp -f ca.pem                       "$EXPORT_OBSERVER_TO/ca.pem"
    verify_export_triple \
        "$EXPORT_OBSERVER_TO/dashboard-observer.pem" \
        "$EXPORT_OBSERVER_TO/dashboard-observer.key" \
        "$EXPORT_OBSERVER_TO/ca.pem"
    echo "  ✓ exported + verified: dashboard-observer.pem, dashboard-observer.key, ca.pem → $EXPORT_OBSERVER_TO"
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
    echo "Monolith .env paths (operational lane, relative to scaffold/):"
    echo "  SECURITY_SERVICE_URL=https://localhost:8443"
    echo "  SECURITY_SERVICE_CLIENT_CERT_PATH=./secrets/monolith-client.pem"
    echo "  SECURITY_SERVICE_CLIENT_KEY_PATH=./secrets/monolith-client.key"
    echo "  SECURITY_SERVICE_CA_PATH=./secrets/ca.pem"
    echo ""
fi
if [[ -n "$EXPORT_OBSERVER_TO" ]]; then
    echo "Monolith .env paths (dashboard observer lane, relative to scaffold/):"
    echo "  SECURITY_SERVICE_READONLY_URL=https://localhost:8443"
    echo "  SECURITY_READONLY_CLIENT_CERT_PATH=./secrets/dashboard-observer.pem"
    echo "  SECURITY_READONLY_CLIENT_KEY_PATH=./secrets/dashboard-observer.key"
    echo "  SECURITY_READONLY_CA_PATH=./secrets/ca.pem"
    echo ""
    echo "Security-service .env — add the observer DN to its allow-list:"
    echo "  SECURITY_DASHBOARD_OBSERVER_SUBJECTS=L=Local,O=WorkAutomations,CN=workautomations-dashboard-observer"
    echo ""
fi
if [[ -n "$EXPORT_ADMIN_TO" ]]; then
    echo "Admin operator workflow (NOT a service env block — the operator runs curl):"
    echo "  # 1. Add the DN to security-service/.env (then restart):"
    echo "  SECURITY_ADMIN_SUBJECTS=L=Local,O=WorkAutomations,CN=workautomations-admin-bootstrap"
    echo "  # 2. Bootstrap the keks row (first KEK lifecycle entry):"
    echo "  curl -sS -k --cert $EXPORT_ADMIN_TO/admin-bootstrap-client.pem \\"
    echo "       --key  $EXPORT_ADMIN_TO/admin-bootstrap-client.key \\"
    echo "       --cacert $EXPORT_ADMIN_TO/ca.pem \\"
    echo "       -X POST https://localhost:8443/v1/admin/rotate-kek"
fi
