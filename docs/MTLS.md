# mTLS

The security service authenticates every inbound call with a verified client certificate.
The TLS engine validates the chain against a configured CA truststore; the application
layer reads the verified leaf cert and binds the caller's identity into the call context
for the duration of the request.

## Cryptographic profile

Per proposal §7.2:

| Parameter | Value |
|-----------|-------|
| TLS version | 1.3 only (no 1.2 fallback) |
| Server key + cert | ECDSA P-384 (`secp384r1`) |
| Client key + cert | ECDSA P-384 (`secp384r1`) |
| Keystore format | PKCS12 (RFC 7292) |
| Truststore format | PKCS12 |

ECDSA P-384 balances 192-bit classical security against cert size; it matches the
~192-bit post-quantum security level of ML-KEM-768.

## Code surface

The authentication path is split into three pieces, each with a clear boundary:

1. **`PeerCertChainExtractor`** (interface) — returns the verified client cert chain for a
   call, or null when none is present. Source:
   [`adapters/inbound/http/.../auth/PeerCertChainExtractor.kt`](../adapters/inbound/http/src/main/kotlin/com/workautomations/security/adapters/inbound/http/auth/PeerCertChainExtractor.kt).

   Three implementations are wired today:
   - `NettySslPeerCertChainExtractor` — the production extractor. Reads the validated peer
     cert chain from the underlying Netty `SslHandler`'s SSL session. Bound by
     `SecurityServiceModule` automatically when `MtlsConfig.fromEnv()` returns a non-null
     config (i.e. when the keystore + truststore env vars are set). Source:
     [`adapters/inbound/http/.../auth/NettySslPeerCertChainExtractor.kt`](../adapters/inbound/http/src/main/kotlin/com/shared/security/adapters/inbound/http/auth/NettySslPeerCertChainExtractor.kt).
   - `DenyAllPeerCertChainExtractor` — fail-closed fallback. Bound automatically when
     `MtlsConfig.fromEnv()` returns null (i.e. when the keystore env vars are unset), so a
     server that boots without TLS rejects every call with 401 rather than silently
     accepting traffic. Plaintext mode is for `./gradlew :infrastructure:run` smoke checks
     only and is never appropriate in deployed environments.
   - `TestPeerCertChainExtractor` — reads a synthetic chain from call attributes. Test-only.

   In docker-compose dev (and the equivalent `./gradlew :infrastructure:run` flow), the
   Netty engine terminates TLS and `NettySslPeerCertChainExtractor` is active. In k3s
   prod, Linkerd's sidecar terminates mTLS upstream and the extractor swaps for a
   sidecar-header reader — see TRUST_MODEL.md §3.

2. **`installMtlsAuth(extractor, auditLog)`** — Ktor `Application` extension. Installs an
   interceptor in the `Plugins` pipeline phase that:
   - calls `extractor.extract(call)`,
   - if null/empty → writes an `MTLS_REJECTED` audit event, returns HTTP 401, and calls
     `finish()` so no downstream route runs,
   - if non-null → constructs a `ClientPrincipal(subjectDn, sha256Fingerprint)` and stores
     it in call attributes.

   Source: [`adapters/inbound/http/.../auth/MtlsAuthPlugin.kt`](../adapters/inbound/http/src/main/kotlin/com/workautomations/security/adapters/inbound/http/auth/MtlsAuthPlugin.kt).

3. **`call.clientPrincipal()`** — extension on `ApplicationCall`. Returns the authenticated
   principal or null. Routes read this to propagate the calling subject DN into audit events
   and into `AdminAllowList` checks.

## Why an unconditional pipeline interceptor and not a `Route.authenticate { }` block

`installMtlsAuth` runs in the `Plugins` phase, **before** routing. Every endpoint of the
security service requires mTLS — there are no exempt routes, not even `/v1/health`.
Putting the auth check in routing would mean each new route author has to remember to wrap
their block in `authenticate { }`; forgetting that is a silent vulnerability. With an
interceptor in `Plugins`, the gate is structurally impossible to bypass.

## Configuration

Environment variables read by `MtlsConfig.fromEnv()`:

| Env var | Default | Required |
|---------|---------|----------|
| `SECURITY_SERVICE_KEYSTORE_PATH` | — | yes (when mTLS is enabled) |
| `SECURITY_SERVICE_KEYSTORE_PASSWORD` | — | yes |
| `SECURITY_SERVICE_KEYSTORE_ALIAS` | `security-service` | no |
| `SECURITY_SERVICE_TRUSTSTORE_PATH` | — | yes |
| `SECURITY_SERVICE_TRUSTSTORE_PASSWORD` | — | yes |

`MtlsConfig.fromEnv()` returns null when any required var is absent — the service falls
back to plaintext mode in that case. The startup log line is loud (`DEV-ONLY: starting
security-service ... WITHOUT mTLS`) and the deny-all extractor rejects every authenticated
endpoint with 401. Plaintext mode is for `./gradlew :infrastructure:run` smoke checks
only; it **must not** ship to any deployed environment.

## TLS termination wiring

`Application.kt::buildServer` branches on `MtlsConfig.fromEnv()`:

- When non-null: installs a Ktor `sslConnector` with the loaded keystore + truststore.
  Ktor 3.x's Netty engine treats a connector with a configured truststore as mTLS-required
  — any client that doesn't present a cert chaining to the truststore is rejected during
  the TLS handshake before reaching application code.
- When null: installs a plaintext `connector` and logs the loud `DEV-ONLY` warning above.

## Cert generation

See [`CERT_GENERATION.md`](CERT_GENERATION.md) for the OpenSSL recipes producing the dev
CA, server cert, and client certs. The fastest path is `./scripts/init-dev-certs.sh`,
which generates everything into `./secrets/` idempotently and (with
`--export-monolith-client-to <dir>`) ships the three client-facing files to the
monolith's own `secrets/` directory.

The test path uses
[`TestCertificateFactory`](../adapters/inbound/http/src/test/kotlin/com/shared/security/adapters/inbound/http/auth/TestCertificateFactory.kt),
which generates ephemeral self-signed ECDSA P-384 certs at test setup time via
BouncyCastle's `JcaX509v3CertificateBuilder`.

## Audit events produced by the auth layer

| Event type | Fires when |
|------------|------------|
| `MTLS_REJECTED` | Inbound call has no verified client cert (`extractor.extract` returned null/empty). |
| `ADMIN_FORBIDDEN` | Authenticated caller's subject DN is not in `AdminAllowList`. |

Stream C swaps the SLF4J fallback writer for the persistent `ExposedAuditLogRepository`
with an HMAC-SHA-512 row chain — see [`AUDIT_LOG.md`](AUDIT_LOG.md) (Stream C).
