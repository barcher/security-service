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

   Two implementations are wired today:
   - `DenyAllPeerCertChainExtractor` — returns null for every call. **The default DI binding
     in `SecurityServiceModule`**, on purpose: until Stream E wires the real Netty/sidecar
     extractor, every call returns 401. Misconfig surfaces as 100% rejection, never as
     silent acceptance.
   - `TestPeerCertChainExtractor` — reads a synthetic chain from call attributes. Test-only.

   Stream E adds the production extractor. The proposal §3.3 / §3.4 anticipates a Linkerd
   service mesh terminating mTLS at a sidecar in k3s prod; the extractor will read the
   PEM-encoded cert from a sidecar-injected header. In docker-compose dev, the extractor
   reads from the Netty SSL session attached to the channel.

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
back to plaintext mode in that case. Plaintext mode is fine for Stream A/B (the
deny-all extractor rejects everything anyway) but **must not** ship to production. Stream E
adds a startup check that refuses to boot in plaintext mode when an env flag indicates a
production deployment.

## Cert generation

Stream E adds `CERT_GENERATION.md` with OpenSSL recipes for producing the dev CA, server
cert, and client certs. Until then, the test path uses
[`TestCertificateFactory`](../adapters/inbound/http/src/test/kotlin/com/workautomations/security/adapters/inbound/http/auth/TestCertificateFactory.kt),
which generates ephemeral self-signed ECDSA P-384 certs at test setup time via
BouncyCastle's `JcaX509v3CertificateBuilder`.

## Audit events produced by the auth layer

| Event type | Fires when |
|------------|------------|
| `MTLS_REJECTED` | Inbound call has no verified client cert (`extractor.extract` returned null/empty). |
| `ADMIN_FORBIDDEN` | Authenticated caller's subject DN is not in `AdminAllowList`. |

Stream C swaps the SLF4J fallback writer for the persistent `ExposedAuditLogRepository`
with an HMAC-SHA-512 row chain — see [`AUDIT_LOG.md`](AUDIT_LOG.md) (Stream C).
