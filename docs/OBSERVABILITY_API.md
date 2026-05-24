# Observability API

Stream L L.0 — read-only HTTP surface under `/v1/observability/` that lets the monolith's
Security tab (and any future operator dashboard) read lifecycle metadata across services
without touching `security_keys.*` tables directly.

Cross-references: [`security_health_dashboard.md`](../../scaffold/docs/proposals/security_health_dashboard.md)
proposal v0.1 (full design), [`KEK_LIFECYCLE.md`](KEK_LIFECYCLE.md),
[`JWT_KEY_LIFECYCLE.md`](JWT_KEY_LIFECYCLE.md), [`AUDIT_LOG.md`](AUDIT_LOG.md).

## 1. Authentication — two gates

1. **Gate 1 — mTLS.** Enforced by `MtlsAuthPlugin` ahead of every route. A request that
   does not present a valid client certificate against the configured truststore is
   rejected during the TLS handshake; it never reaches application code.
2. **Gate 2 — observer allow-list.** `DashboardObserverAllowList.isObserver(subjectDn)`
   is consulted by each route handler. Mismatch returns `403 observer_required` and
   writes an `OBSERVER_FORBIDDEN` audit row.

The two gates are intentionally distinct from the admin lane. The four-lane subject-DN
model means:

| Lane | DN convention | Env var | Allowed surfaces |
|---|---|---|---|
| Operational | `CN=workautomations-<service>,O=WorkAutomations` | `SECURITY_OPERATIONAL_CLIENT_SUBJECTS` | `/v1/dek/*`, `/v1/jwt/sign` |
| Admin | `CN=workautomations-admin-<id>,O=WorkAutomations` | `SECURITY_ADMIN_SUBJECTS` | `/v1/admin/*` |
| **Dashboard observer** | `CN=workautomations-dashboard-observer,O=WorkAutomations` | `SECURITY_DASHBOARD_OBSERVER_SUBJECTS` | `/v1/observability/*` (this surface) |
| Operator decrypt (Stream M) | `CN=workautomations-operator-decrypt-<email-hash>,O=WorkAutomations` | `SECURITY_OPERATOR_DECRYPT_SUBJECTS` | None — CLI-only, not via HTTP |

A leaked observer cert can read lifecycle metadata but cannot rotate, unwrap, sign, or
mint keys. The audit chain records the actor subject DN on every observation call so
forensics can distinguish dashboard reads from operational crypto calls structurally.

## 2. Endpoints

All five GETs are mounted under `/v1/observability/`. Every successful call writes
**exactly one** `DASHBOARD_OBSERVED` audit row regardless of result-set size.

### 2.1. `GET /v1/observability/keks`

Lists every row in `keks` (STAGED, ACTIVE, PRIOR, RETIRED) ordered by `created_at` desc.

```http
GET /v1/observability/keks
```

```json
{
  "keks": [
    {
      "id": "9d3e8a30-1234-...",
      "fingerprint": "fp:a1b2c3d4",
      "status": "ACTIVE",
      "createdAt": "2026-05-23T12:00:00Z",
      "activatedAt": "2026-05-23T12:00:00Z",
      "quiescedAt": null,
      "retiredAt": null
    }
  ]
}
```

**Strips:** nothing — `KekRecord` is already metadata-only; key bytes live in the
HSM/mount, never in this row.

### 2.2. `GET /v1/observability/deks?limit=50`

Returns the most recent `limit` DEK rows + total population count.

```http
GET /v1/observability/deks?limit=20
```

```json
{
  "deks": [
    {
      "handleHex": "9d3e8a30...",
      "kekId": "9d3e8a30-1234-...",
      "createdAt": "2026-05-23T12:00:00Z",
      "updatedAt": "2026-05-23T12:00:00Z"
    }
  ],
  "totalCount": 12345
}
```

**Strips:** `wrappedDekBytes`. The DTO has no field for it. Cap: `limit ≤ 200`.

### 2.3. `GET /v1/observability/jwt-signing-keys`

Lists every row in `jwt_signing_keys` ordered by `created_at` desc.

```json
{
  "keys": [
    {
      "kidHex": "9d3e8a30...",
      "status": "ACTIVE",
      "algorithm": "ES256",
      "curve": "P-256",
      "wrappedUnderKekId": "9d3e8a30-1234-...",
      "createdAt": "2026-05-23T12:00:00Z",
      "activatedAt": "2026-05-23T12:00:00Z",
      "quiescedAt": null,
      "retiredAt": null,
      "retainUntil": null
    }
  ]
}
```

**Strips:** `wrappedPrivateKeyBytes` AND `publicKeySpki`. The SPKI is published via
`/v1/jwks` for verification; it doesn't belong on the dashboard surface.

### 2.4. `GET /v1/observability/audit-events`

Faceted query against `audit_events`. Strips `prev_hmac` + `row_hmac` at the persistence
boundary; the wire DTO has no field for either.

Query parameters:

| Param | Default | Notes |
|---|---|---|
| `q` | — | Case-insensitive substring match across `event_type`, `actor_subject`, `kek_id`. |
| `eventTypeFilter` | — | Comma-separated list of event types, e.g. `KEK_ACTIVATED,DEK_UNWRAPPED`. |
| `fromIso` | — | ISO-8601 instant, inclusive lower bound on `occurred_at`. |
| `toIso` | — | ISO-8601 instant, inclusive upper bound on `occurred_at`. |
| `page` | `0` | 0-based page index. |
| `size` | `50` | Page size. Server clamps to ≤ 200. |

```json
{
  "items": [
    {
      "id": 4321,
      "occurredAt": "2026-05-23T12:00:00Z",
      "eventType": "DEK_UNWRAPPED",
      "actorSubject": "CN=workautomations-monolith,O=WorkAutomations",
      "kekId": "9d3e8a30-1234-...",
      "dekHandleHex": "ab12cd34...",
      "success": true,
      "detailJson": "{\"algorithm\":\"ML-KEM-768/AES-256-GCM\"}"
    }
  ],
  "totalCount": 999_999,
  "page": 0,
  "pageSize": 50
}
```

### 2.5. `GET /v1/observability/recent-rotations?n=20`

Convenience query — last `n` rows where `event_type` is one of the rotation lifecycle
events: `KEK_ACTIVATED`, `KEK_RETIRED`, `DEK_ROTATION_BATCH_OK`, `JWKS_KEY_ACTIVATED`,
`JWKS_KEY_RETIRED`. The filter set is hard-coded in the use case so this endpoint cannot
be used to query arbitrary event types.

```json
{
  "rotations": [
    {
      "id": 4321,
      "occurredAt": "2026-05-23T12:00:00Z",
      "eventType": "KEK_ACTIVATED",
      "actorSubject": "CN=workautomations-admin-1,O=WorkAutomations",
      "kekId": "9d3e8a30-1234-...",
      "detailJson": "{\"fingerprint\":\"fp:a1b2c3d4\"}"
    }
  ]
}
```

Cap: `n ≤ 100`.

## 3. Error catalog

| HTTP | `error` | When |
|---|---|---|
| 401 | `mtls_required` | mTLS principal missing (route-layer guard). |
| 403 | `observer_required` | Gate-2 allow-list denied this subject DN. |
| 422 | `malformed_request` | Query parameter parse failure (e.g. invalid ISO instant). |
| 429 | `rate_limited` | Per-subject token-bucket cap exceeded. |
| 500 | `internal_error` | Unexpected exception; an `OBSERVABILITY_ERROR` audit row is written before responding. |

Every error path EXCEPT the 401 (which fires before app code runs) writes a structured
audit row, so operator forensics has a complete picture of every observation attempt.

## 4. Configuration

| Env var | Default | Purpose |
|---|---|---|
| `SECURITY_DASHBOARD_OBSERVER_SUBJECTS` | (empty → deny all) | Semicolon-separated RFC2253 DNs allowed to call `/v1/observability/*`. Falls back to comma-separation only when no `;` is present. |
| `SECURITY_RATE_LIMIT_ENABLED` | `true` | Master toggle for the per-subject rate limiter. The same limiter that gates `/v1/dek/unwrap` also gates the observability endpoints (sharing the bucket per subject is intentional — a single observer cert can spike either). |
| `SECURITY_RATE_LIMIT_CAPACITY` | `5` | Token-bucket capacity. |
| `SECURITY_RATE_LIMIT_REFILL_PER_SEC` | `1.0` | Token-bucket refill rate. |

The observability rate-limit budget intentionally lives under the same `SECURITY_RATE_LIMIT_*`
env vars as `/v1/dek/unwrap` for K.0 simplicity. A future stream may add a dedicated
`SECURITY_OBSERVABILITY_RATE_LIMIT_*` family if dashboards need a separate budget.

## 5. Audit-event emission semantics

| When | Event type | Notes |
|---|---|---|
| Every successful call | `DASHBOARD_OBSERVED` | ONE row per call regardless of result-set size. `detail_json` includes `resource`, `rowCount`, `totalCount` (where applicable), `page`/`size` (audit-events only). |
| 403 (observer not allowlisted) | `OBSERVER_FORBIDDEN` | `detail_json` includes the endpoint path. |
| 429 (rate-limit exceeded) | `OBSERVABILITY_RATE_LIMIT_EXCEEDED` | `detail_json` includes the endpoint path. |
| 500 (unexpected exception) | `OBSERVABILITY_ERROR` | `detail_json` includes the endpoint path + exception class name (NOT the stack trace; that goes to slf4j). |

## 6. Threat model — what an observer can / cannot do

* **Can read:** every column of `keks` / `deks` / `jwt_signing_keys` EXCEPT the wrapped
  key bytes and the public SPKI. Every column of `audit_events` EXCEPT `prev_hmac` /
  `row_hmac`.
* **Cannot read:** any wrapped key bytes (DEK bytes, JWT private bytes), any KEK material,
  any audit-chain HMAC bytes.
* **Cannot write:** anything. The port for this surface is read-only at the type level
  (`AuditLogQueryPort` has only `search`; the write port `AuditLogPort` is not bound into
  the observability code path).
* **Cannot rotate / unwrap / sign:** the observer DN is structurally not in `AdminAllowList`,
  so `/v1/admin/*` returns 403. The observer DN is not in any other allow-list either,
  so `/v1/dek/*` and `/v1/jwt/sign` also return 403 (no matching write path).

A compromised observer cert therefore yields read access to lifecycle metadata only —
useful for an attacker to map your rotation cadence, but not enough to forge a signature,
unwrap a DEK, or rewrite the chain.

## 7. Sample mTLS curl invocations

```bash
# Replace the CN with whatever's in SECURITY_DASHBOARD_OBSERVER_SUBJECTS.
CERT=./secrets/dashboard-observer-client.crt
KEY=./secrets/dashboard-observer-client.key
CA=./secrets/security-service-ca.crt

# 1) List KEKs
curl -sS \
    --cert "$CERT" --key "$KEY" --cacert "$CA" \
    https://security-app:8443/v1/observability/keks | jq

# 2) List recent DEKs, cap 20
curl -sS \
    --cert "$CERT" --key "$KEY" --cacert "$CA" \
    'https://security-app:8443/v1/observability/deks?limit=20' | jq

# 3) Search audit events for KEK rotations in the last 24h
curl -sS \
    --cert "$CERT" --key "$KEY" --cacert "$CA" \
    'https://security-app:8443/v1/observability/audit-events?eventTypeFilter=KEK_ACTIVATED,KEK_RETIRED&fromIso=2026-05-22T00:00:00Z&size=100' | jq

# 4) Recent rotations convenience query
curl -sS \
    --cert "$CERT" --key "$KEY" --cacert "$CA" \
    'https://security-app:8443/v1/observability/recent-rotations?n=10' | jq
```
