#!/usr/bin/env bash
# seed-dev-kek-row.sh — DEV ONLY. Insert the first `keks` row referencing the current
# env-var KEK, marking it ACTIVE so the KEK lifecycle state machine has an anchor.
#
# Why this exists: `POST /v1/admin/rotate-kek` generates new keypair material but does
# NOT persist a row — per docs/KEK_LIFECYCLE.md §4, the operator is responsible for the
# insert + status flip after installing the private key in the secret store. In
# production the operator runs SQL through a runbook procedure. In dev that procedure
# is this script: it reads the CURRENT public key from security-service/.env, computes
# the SHA-256 colon-hex fingerprint that the schema expects, and inserts a single row
# with status=ACTIVE (skipping the STAGED → ACTIVE flip because there is no prior key
# to demote on first bootstrap).
#
# Idempotent: re-running is a no-op if a row with the same fingerprint already exists.
#
# PRODUCTION: do NOT run this. Production rotates via `POST /v1/admin/rotate-kek` +
# operator SQL on the prod database. The audit chain assumes every keks row was created
# by a real rotation event, not a script.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$SECURITY_ROOT/.env"

# ── Read CURRENT public key from .env ────────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
    echo "FATAL: $ENV_FILE missing. Run init-dev-certs.sh + populate ML_KEM_*_CURRENT first." >&2
    exit 1
fi

# Extract ML_KEM_PUBLIC_KEY_CURRENT — strip any inline comment, quotes, trailing whitespace.
PUBLIC_KEY_B64="$(awk -F= '/^ML_KEM_PUBLIC_KEY_CURRENT=/ {sub(/^ML_KEM_PUBLIC_KEY_CURRENT=/, ""); print; exit}' "$ENV_FILE" \
    | sed 's/^"//; s/"$//; s/[[:space:]]*$//')"

if [[ -z "$PUBLIC_KEY_B64" ]]; then
    echo "FATAL: ML_KEM_PUBLIC_KEY_CURRENT is empty in $ENV_FILE." >&2
    echo "       Run \`./gradlew :infrastructure:run --args=\"generate-kek\"\` first, paste the" >&2
    echo "       printed KEY=VALUE lines into security-service/.env." >&2
    exit 1
fi

# ── Fingerprint = SHA-256(public key bytes), colon-hex (95 chars) ────────────────
# The schema column `fingerprint` is VARCHAR(95) and matches what the JdkSslContext
# code path produces via `MessageDigest.getInstance("SHA-256").digest(bytes)` rendered
# with `joinToString(":") { "%02x".format(it) }`.
# LibreSSL's `openssl base64 -d` silently emits 0 bytes for single-line input >76 chars
# unless `-A` is passed. Use the plain `base64` decoder which works the same on macOS
# (LibreSSL-shipped) and Linux (GNU coreutils).
FINGERPRINT="$(printf '%s' "$PUBLIC_KEY_B64" \
    | base64 -d 2>/dev/null \
    | openssl dgst -sha256 -binary \
    | xxd -p -c 32 \
    | head -c 64 \
    | sed 's/\(..\)/\1:/g; s/:$//')"

# Guard against the well-known SHA-256 of the empty string — that's what we'd compute if
# the base64 decode silently produced 0 bytes.
EMPTY_SHA256_PREFIX="e3:b0:c4:42"
if [[ "$FINGERPRINT" == "$EMPTY_SHA256_PREFIX"* ]]; then
    echo "FATAL: fingerprint = SHA-256(empty string). The base64 decode produced 0 bytes," >&2
    echo "       which usually means ML_KEM_PUBLIC_KEY_CURRENT is empty in .env or the base64" >&2
    echo "       decoder rejected the input. Inspect $ENV_FILE and re-run." >&2
    exit 1
fi

if [[ ${#FINGERPRINT} -ne 95 ]]; then
    echo "FATAL: computed fingerprint length is ${#FINGERPRINT}, expected 95." >&2
    echo "       Got: $FINGERPRINT" >&2
    exit 1
fi

# ── DB connection params (env override + sensible dev defaults) ──────────────────
DB_HOST="${SECURITY_DB_HOST:-localhost}"
DB_PORT="${SECURITY_DB_PORT:-3308}"
DB_NAME="${SECURITY_DB_NAME:-security_keys}"
DB_USER="${SECURITY_DB_USER:-security}"
DB_PASS="${SECURITY_DB_PASSWORD:-changeme}"

ROW_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"

echo "==> Seeding dev KEK row"
echo "    fingerprint = $FINGERPRINT"
echo "    new row id  = $ROW_ID"

# ── Insert (or skip if fingerprint already present) ──────────────────────────────
SQL=$(cat <<EOF
INSERT INTO keks (id, fingerprint, status, created_at, activated_at)
SELECT '$ROW_ID', '$FINGERPRINT', 'ACTIVE', NOW(6), NOW(6)
WHERE NOT EXISTS (
    SELECT 1 FROM keks WHERE fingerprint = '$FINGERPRINT'
);
SELECT id, status, fingerprint FROM keks ORDER BY created_at DESC;
EOF
)

if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^security-service-db$'; then
    echo "    (using docker exec security-service-db)"
    docker exec -i security-service-db mysql -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" 2>&1 \
        | grep -v -E "^mysql: \[Warning\] Using a password" \
        || true
fi 2>/dev/null <<<"$SQL"

# Fall back to host mysql client if docker exec path didn't run
if ! command -v docker >/dev/null 2>&1 || ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^security-service-db$'; then
    if ! command -v mysql >/dev/null 2>&1; then
        echo "FATAL: neither 'docker' (with security-service-db running) nor 'mysql' CLI found." >&2
        exit 1
    fi
    mysql -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" <<<"$SQL"
fi

echo ""
echo "Done. Next step: ./gradlew :infrastructure:run --args=\"jwt-keys generate-pair --activate\""
