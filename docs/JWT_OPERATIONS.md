# JWT operations

Reference for the two HTTP surfaces the security service exposes for JWT issuance and
verification: `POST /v1/jwt/sign` (mTLS-required) and `GET /v1/jwks` (public).

This document covers Stream K **K.0** scope only: the server-side endpoints, the wire
contract, the caller-authentication model, and the error catalog. K.1 (consumer JWT
client in the shared-security-client) and K.2/K.3 (cutover sequencing in the monolith)
are tracked in their own proposals.

## 1. `POST /v1/jwt/sign`

Mints an ES256 JWT for a mTLS-authenticated caller.

### 1.1. Authentication — two gates

1. **Gate 1 — mTLS.** Enforced by `MtlsAuthPlugin` ahead of the route. A request that
   does not present a valid client certificate against the configured truststore is
   rejected during the TLS handshake; it never reaches application code. The route
   returns `401 mtls_required` if the principal is unexpectedly absent (programming
   error path, not the normal denial path).
2. **Gate 2 — audience allow-list.** `JwtAudienceAllowList.isAllowed(subjectDn,
   audience)` is consulted by `SignJwtUseCase`. Mismatch returns `403 audience_forbidden`
   and writes a `JWT_AUDIENCE_FORBIDDEN` audit row. The allow-list is sourced from the
   `SECURITY_JWT_AUDIENCE_ALLOWLIST` env var (see §4).

The two gates are intentionally distinct. Gate 1 proves "you are who you say you are";
Gate 2 proves "you're allowed to ask for tokens with this `aud`". A leaked operational
mTLS cert from one service therefore cannot mint tokens for an audience owned by a
different service.

### 1.2. Request

```http
POST /v1/jwt/sign HTTP/1.1
Content-Type: application/json
```

```json
{
  "subject": "user-42",
  "audience": "workautomations-api",
  "issuer": "security-service",
  "expiresInSeconds": 300,
  "extraClaims": { "role": "ACCOUNT_OWNER" }
}
```

| Field | Type | Notes |
|---|---|---|
| `subject` | string | Becomes the JWT `sub` claim. |
| `audience` | string | Becomes the JWT `aud` claim AND is checked against Gate 2. |
| `issuer` | string | Becomes the JWT `iss` claim. Convention: `"security-service"`. |
| `expiresInSeconds` | long | TTL of the access token, ≤ 86 400 (24 h cap). |
| `extraClaims` | object | Optional. Merged into the JWT payload after the standard claims. |

### 1.3. Response — success

```json
{
  "token": "<header>.<payload>.<signature>",
  "kidHex": "9d3e8a...",
  "expiresAt": 1716470000
}
```

`token` is the RFC 7519 compact serialization. `kidHex` matches the `kid` in the JWS
header (32 lowercase hex chars). `expiresAt` is the JWT's `exp` claim in epoch seconds.

### 1.4. JWS header

The signed JWT header is fixed:

```json
{ "alg": "ES256", "typ": "JWT", "kid": "<kidHex>" }
```

ES256 = ECDSA P-256 + SHA-256 per RFC 7518 §3.4. The signature is the raw R || S form
(64 bytes), base64url-encoded without padding.

### 1.5. Error catalog

| HTTP | `error` | When |
|---|---|---|
| 401 | `mtls_required` | mTLS principal missing (route-layer guard). |
| 403 | `audience_forbidden` | Gate-2 allow-list denied this subject DN for this audience. |
| 422 | `malformed_request` | `expiresInSeconds` outside [1, 86 400] or body invalid. |
| 503 | `no_active_key` | No ACTIVE JWT signing key configured. Operator action required. |

Every error path writes a corresponding audit event (`JWT_AUDIENCE_FORBIDDEN`,
`JWT_SIGN_FAILED`) so failed mints are observable in the audit chain.

## 2. `GET /v1/jwks`

Public JSON Web Key Set per RFC 7517. Returns every publishable key (status ∈ {ACTIVE,
PRIOR}).

### 2.1. Response

```http
GET /v1/jwks HTTP/1.1
Host: security-app:8443
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=300
```

```json
{
  "keys": [
    {
      "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
      "kid": "9d3e8a...",
      "x": "<base64url-X>",
      "y": "<base64url-Y>"
    }
  ]
}
```

### 2.2. Cache semantics

The 5 min `Cache-Control: public, max-age=300` is a deliberate balance between
propagation latency for newly-activated keys and load on the endpoint. The consuming
shared-security-client (K.1) refreshes hourly on the normal path AND eagerly on a
`kid` cache-miss, so even immediately after activation a consumer never falls more
than one request behind.

### 2.3. What's NOT in JWKS

* STAGED keys (not yet active; would be a noop for consumers).
* QUIESCED + RETIRED keys (consumers must reject tokens signed by them).
* Any private-key material — the endpoint emits only the EC public point.

### 2.4. Authentication

None. JWKS is intentionally public so JWT verification is a pure-CPU operation in any
consumer (no per-request remote call to the security service).

## 3. Audit events emitted

| Event | When |
|---|---|
| `JWT_SIGNED` | A `/v1/jwt/sign` request succeeded. Records kid, audience, subject, exp. |
| `JWT_AUDIENCE_FORBIDDEN` | Gate-2 denied a request. Records audience. |
| `JWT_SIGN_FAILED` | Sign step threw, or no ACTIVE key. Records reason. |

The JWKS GET endpoint does NOT write per-request audit rows (it's a public read of
already-public data); enabling that would flood the chain.

## 4. Configuration

| Env var | Purpose |
|---|---|
| `SECURITY_JWT_AUDIENCE_ALLOWLIST` | Comma-separated `<subject-dn-hash>=<audience>` pairs. The hash is the first 16 lowercase hex chars of `SHA-256(subjectDn.lowercase().trim())`. Empty → deny everything. |

Example:

```
SECURITY_JWT_AUDIENCE_ALLOWLIST="a1b2c3d4e5f60718=workautomations-api,a1b2c3d4e5f60718=workautomations-internal,f9e8d7c6b5a40312=financial-api"
```

Operators derive subject-DN hashes via `EnvJwtAudienceAllowList.hashSubject(dn)` — the
function is exposed for runbook use and matches the parser's hashing exactly.

## 5. Cross-references

* Lifecycle states + Quartz jobs: [`JWT_KEY_LIFECYCLE.md`](JWT_KEY_LIFECYCLE.md).
* Operator key ceremony (initial setup + rotation): [`HSM_KEY_CEREMONY.md`](HSM_KEY_CEREMONY.md).
* Cutover from monolith HS256 → security-service ES256: [`JWT_CUTOVER.md`](JWT_CUTOVER.md).
