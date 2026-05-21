# Trust Model

> **Audience.** Someone reading the security service repo cold — operator, auditor, new
> contributor. Self-contained: every statement here can be verified against the files in
> this repo without referring to the monolith. Cross-repo references are marked clearly.
>
> **What this doc answers.**
> 1. Which trust authorities exist, and where each one's private key lives.
> 2. How that changes between dev (this script-driven setup) and prod (Linkerd + offline trust anchor).
> 3. Why the security service is the *trust primitive* of the multi-service system, and what
>    "trust primitive" means in practice.

---

## 1. Three distinct trust authorities

The system has three different cryptographic trust relationships. They are often conflated;
they should not be.

| # | Trust authority | Purpose | Private key lives... (dev) | Private key lives... (prod) | Rotation cadence |
|---|---|---|---|---|---|
| 1 | **Workload identity (mTLS)** | Authenticate every service-to-service call inside the trust boundary. Server cert proves "I am `security-app`"; client cert proves "I am `monolith`". | `security-service/secrets/ca.key` (this repo) | Linkerd identity issuer (a k8s Secret), itself signed by an **offline trust anchor whose private key never exists as bytes outside a physical HSM** — see §3. | Issuer: 90 days. Workload certs: **24 h**. |
| 2 | **Ingress CA** | Authenticate the perimeter to external callers. | N/A — security-service has no public ingress in any environment | N/A — security-service has no public ingress in any environment | N/A |
| 3 | **Data-protection KEK (ML-KEM-768)** | Wrap/unwrap DEKs used to encrypt principal data at rest. Has **nothing to do with TLS**. | `security-service/secrets/ml_kem_private_key` | KEK bytes are **wrapped by an HSM-resident key**; only the wrapped form is mounted at `$KEK_MOUNT_DIR`. Unwrap happens once at boot via PKCS#11 — see §3.5. | Operator-controlled. `KekRotationJob` runs the rewrap; the cadence is config-driven (`DEK_ROTATION_CRON`, `KEK_PRIOR_TTL_CRON`). |

If you remember only one thing: **(1) and (3) are different keys with different lifecycles.**
The mTLS CA proves identity at the network layer. The KEK protects data at rest. A
compromise of one does not implicate the other.

---

## 2. Dev trust model — security-service IS the CA

In dev there is no service mesh. To exercise the mTLS handshake locally we need *some* CA,
and the most honest place to put it is inside the service that owns the trust role anyway.

### 2.1 File layout

The cert generator (`scripts/init-dev-certs.sh`) populates `security-service/secrets/`:

```
security-service/
└── secrets/                          # gitignored
    ├── ca.key                        # CA private key — NEVER copied outside this dir
    ├── ca.pem                        # CA public cert — distributed to clients (see §2.3)
    ├── server.key                    # server private key (ECDSA P-384)
    ├── server.pem                    # server cert signed by ca.key
    ├── keystore.p12                  # (server.pem + server.key) packaged for Ktor TLS
    ├── truststore.p12                # ca.pem packaged for inbound client-cert validation
    ├── audit_hmac_key                # 64-byte base64 — separate trust authority from (1)+(3)
    ├── ml_kem_public_key             # KEK public — used by `KekProvider` wrap path
    └── ml_kem_private_key            # KEK private — used by `KekProvider` unwrap path
```

`secrets/` is `.gitignored`. No file in this directory is ever committed.

### 2.2 Why the CA private key lives in security-service/secrets/

Three reasons:

1. **The security service is already the trust authority for (3).** Adding (1) to the same
   directory does not increase the blast radius — anyone who can read `ca.key` can already
   read `ml_kem_private_key`, and the latter is the more sensitive secret (it protects
   actual customer data; the CA only authenticates network calls).
2. **No abstract dependencies.** A neutral `workAutomations/dev-ca/` workspace shared by
   both services would create a third runtime dependency neither service should know
   about. Putting the CA inside the service that mints trust artifacts means each
   consuming service still reads only from its own `secrets/`.
3. **The dev-to-prod analogy is direct.** In prod, Linkerd's identity issuer plays this
   role — it lives *adjacent to* the workload, not inside a "dev CA" peer service. Putting
   our dev CA inside the security service mirrors the prod arrangement (issuer + workload
   co-located), just without the sidecar.

### 2.3 Setup-time export — never a runtime read

Each consuming service holds only what it needs *at runtime*. The monolith, for example,
needs three files: its client cert, its client key, and the CA public cert. These three
files are *copied* into `scaffold/secrets/` once, at setup time, by:

```bash
security-service/scripts/init-dev-certs.sh --export-monolith-client-to ../scaffold/secrets
```

After this one-shot copy:

- The monolith reads only `scaffold/secrets/{monolith-client.pem, monolith-client.key, ca.pem}`.
- The monolith never reads `../security-service/...` at runtime. Its `.env` contains no
  cross-service paths.
- The CA *private* key (`ca.key`) never leaves `security-service/secrets/`. Only the CA
  *public* cert (`ca.pem`) is exported.

**This is structurally identical to a prod CA workflow.** In prod, a PKI team issues the
client cert from their CA and ships it to the consuming service via secret management.
The consuming service then reads only from its own secret mount. Here in dev, the security
service plays the PKI team's role, and the "ship it via secret management" step is a `cp`.

### 2.4 What invalidates this design

If we ever needed a third sibling service (call it `analytics-service`) that also speaks
mTLS to security-service, the dev CA pattern still scales — `init-dev-certs.sh` would
grow `--export-analytics-client-to <dir>`. Each new client receives an issued cert + the
CA public cert; the CA private key still never leaves `security-service/secrets/`. The
moment the dev pattern requires more than `cp` to deliver certs (multi-cluster, automated
rotation, hardware tokens), it's time to graduate to a real PKI — see §3.

---

## 3. Prod trust model — Linkerd identity + HSM-rooted trust anchor

The dev CA pattern works because there are two services on one laptop. Production has
multiple replicas, rolling deploys, certificate rotation, and audit requirements that
make manual `cp` operations unsuitable.

**The canonical prod assumption:** the root CA private key lives in a **physical hardware
security module (HSM)** held by the operator. It never exists as bytes on any networked
host, at any time. Cloud-managed KMS services (HashiCorp Vault PKI, AWS KMS, GCP Cloud KMS)
are *alternatives* to a physical HSM, not the default — see §3.6.

### 3.1 What replaces what

| Dev artifact | Prod replacement | Why |
|---|---|---|
| `security-service/secrets/ca.key` (CA private key) | **HSM-resident root key.** The private key is generated on the HSM and never exported. All signing operations (issuing the Linkerd identity issuer; rotating it) are performed by the HSM via PKCS#11; only the *signed result* is extractable. | The trust anchor signs the online identity issuer once at install and is then needed only when rotating issuers (typically annual). Keeping the root in hardware means a cluster compromise, a cloud-provider compromise, AND a server-side network compromise cannot yield the root key. Only physical access to the HSM does. |
| `security-service/secrets/server.key` + `server.pem` | **Linkerd-injected workload cert.** Linkerd's identity controller mints a fresh server cert for every pod on startup, signed by the in-cluster identity issuer. Cert lives in pod memory only; never persisted. | Auto-rotation every 24 h; no per-pod key management; no cert files on disk. |
| `scaffold/secrets/monolith-client.pem` | **Linkerd-injected workload cert** on the monolith pod, with a SPIFFE-style identity (`monolith.workautomations.svc.cluster.local`). | Same auto-rotation; identity is bound to the pod's k8s ServiceAccount, not a static file. |
| `scaffold/secrets/ca.pem` (trust anchor cert) | **Trust anchor public cert** distributed to every Linkerd-injected pod via the `linkerd-identity-trust-roots` ConfigMap. (Only the public cert — the private key stays in the HSM.) | Trust anchor *public* material is non-sensitive; rotation happens by updating the ConfigMap and rolling. |

### 3.2 What stays the same

The **security service's view of mTLS is identical** in dev and prod:

- It presents a server cert signed by *some* CA.
- It validates client certs signed by *some* CA.
- It logs the caller's subject DN into the audit chain.

Whether "some CA" is `ca.key` on disk, an HSM-rooted Linkerd issuer, or (in §3.6) a
cloud-KMS-rooted Linkerd issuer is transparent to every line of code in
`adapters/inbound/http/auth/MtlsAuthPlugin.kt`. The trust authority *changes operator*;
the contract does not. This is why the production design can be pre-wired without
changing application code today.

### 3.3 The KEK still lives inside the service — but is HSM-wrapped

Trust authority (3) — the ML-KEM-768 KEK — does **not** move to the mesh in prod. It
remains inside `security-service`, mounted from a k8s Secret at `$KEK_MOUNT_DIR`. This is
because the KEK protects data *at rest*, not data *in flight*. The mesh terminates TLS
between pods; the KEK encrypts bytes that live in the database long after any TLS
session has closed. Different concern, different authority, different rotation cadence.

**ML-KEM-768 is post-quantum and not natively supported by commodity HSMs as of 2026.**
The prod pattern is therefore:

1. **An HSM-resident AES-256 wrapping key** (call it `KEK_WRAPPING_KEY`) is generated on
   the HSM at install time. It never leaves the HSM.
2. The ML-KEM-768 KEK private key is generated *once*, off-cluster, and immediately
   wrapped under `KEK_WRAPPING_KEY` (HSM AES-256-GCM-WRAP call via PKCS#11). Only the
   wrapped blob is shipped to k8s.
3. `$KEK_MOUNT_DIR` holds the wrapped blob, the public KEK, and a small bootstrap
   manifest pointing at the HSM (PKCS#11 slot + label).
4. At boot, `KekProvider` calls PKCS#11 to unwrap the KEK. The unwrapped KEK lives only
   in process memory; it is zeroised on shutdown.
5. The plaintext ML-KEM private key never appears outside the security service process,
   and never appears at all without an active PKCS#11 session to the HSM.

This is "HSM-as-root-of-trust for the KEK lineage" — exactly the same shape as the mTLS
CA, applied to a different trust authority. See §4 for the architectural seam this
imposes on `KekProvider`.

### 3.4 Rotation in prod

| Material | Authority | Rotation trigger | Tool |
|---|---|---|---|
| Workload certs (server, client) | Linkerd identity issuer | Every 24 h, automatic | Linkerd identity controller |
| Linkerd identity issuer | HSM-resident root key | Every 90 days (Linkerd default) | `step certificate sign --kms pkcs11:slot-id=0;object=root-ca` from the operator's offline workstation, HSM plugged in. The HSM signs; the resulting issuer is uploaded to k8s; the HSM is unplugged and returned to physical custody. |
| HSM-resident root key | Operator + physical access to the HSM | Every 3–5 years, or on HSM compromise / lost-token | New HSM provisioning ceremony (multi-person quorum recommended). Outside the cluster's reach by construction. |
| KEK wrapping key | HSM | Operator-driven; co-rotated with the KEK | PKCS#11 `C_GenerateKey` on the HSM; old wrapping key retained until every wrapped artifact is re-wrapped. |
| ML-KEM KEK | Operator + HSM | Operator-driven; `KekRotationJob` performs the on-cluster work | Manual `POST /v1/admin/rotate-kek` triggers the in-cluster job; the new KEK is then HSM-wrapped before persistence. |
| Audit HMAC key | Operator | Long-lived; rotation re-keys every existing audit row | Out of scope here; see `docs/AUDIT_LOG.md`. |

### 3.5 Why an HSM, not a cloud KMS, as the canonical assumption

Cloud KMS (Vault PKI, AWS KMS, GCP Cloud KMS, Azure Key Vault) is operationally cheaper —
no hardware to ship, no physical custody procedures, native rotation tooling. But it has
two trust properties an HSM does not:

| Property | Physical HSM | Cloud KMS |
|---|---|---|
| Root key bytes ever exist outside the operator's custody | No | Yes — they exist on the provider's hardware, under the provider's control |
| Compromise scope of a provider/cloud-account breach | Zero | Catastrophic |
| FedRAMP High / IL5 / classified workloads | Native fit | Requires GovCloud + additional attestation |
| Operator-only physical seizure capability | Yes | No (provider can be subpoenaed, breached, or lock you out) |

The Phase-14 architecture is **pre-wired for HSM** because the data the security service
protects (ACCOUNT_OWNER principal data, financial vault material, AI prompts) is
governance-sensitive enough that "the provider can read it under legal compulsion" is a
disqualifying property. Cloud KMS remains a valid *alternative* (§3.6) — but it is a
deliberate downgrade, not the default.

### 3.6 Alternative: cloud-KMS-rooted (for environments where HSM is infeasible)

If a physical HSM is not available — e.g. early-stage operator, multi-region deployments
where shipping the HSM is impractical, or environments where the threat model already
trusts the cloud provider — the same architecture works with a cloud KMS substituted for
the HSM. The seams (§4) do not change.

| HSM step | Cloud KMS equivalent |
|---|---|
| `step certificate sign --kms pkcs11:slot-id=0;object=root-ca` | `step certificate sign --kms vaultkms:transit/root-ca` (or `awskms:`, `gcpkms:`, `azurekms:`) |
| PKCS#11 unwrap of KEK at boot | `vault.transit.decrypt` / `kms.Decrypt` / `cloudkms.cryptoKeyVersions.decrypt` |
| HSM PKCS#11 driver | KMS provider's SDK or `step-kms-plugin` |

The downgrade is real but the code path is the same — `KekProvider` calls a `KmsClient`
port; whether that port is backed by PKCS#11 or a cloud KMS SDK is a deployment-time
choice. Pre-wiring this means the migration HSM ↔ cloud KMS is a config change, not a
refactor.

---

## 4. Pre-wiring the code for HSM (or KMS) integration

The dev pattern reads KEK bytes directly from a file (`./secrets/ml_kem_private_key`).
The prod pattern unwraps an HSM-wrapped blob at boot via PKCS#11. Both produce a
plaintext ML-KEM private key in process memory. **For the code to absorb both shapes
without a rewrite, the seam must live behind a port** — `KekProvider` cannot embed
"read a file" as an architectural assumption.

The current code path:

```
KekProvider (interface)
  └── FileMountKekProvider (Stream A impl — reads files at $KEK_MOUNT_DIR)
        └── reads ml_kem_public_key + ml_kem_private_key as raw bytes
```

The HSM-ready evolution:

```
KekProvider (interface)
  ├── FileMountKekProvider          ← dev / cloud-KMS-disabled
  └── HsmUnwrappingKekProvider      ← prod default
        ├── KmsClient (interface)
        │     ├── Pkcs11KmsClient          ← HSM via PKCS#11
        │     ├── VaultTransitKmsClient    ← HashiCorp Vault transit
        │     ├── AwsKmsClient             ← AWS KMS
        │     └── ...
        ├── reads wrapped_ml_kem_private_key + bootstrap manifest from $KEK_MOUNT_DIR
        └── calls kmsClient.unwrap(...) once at startup; zeroises on shutdown
```

**Pre-wiring action items** (tracked under Phase-14 follow-ups, not yet implemented):

| Item | Status | Note |
|---|---|---|
| `KekProvider` is already an interface, not a concrete class | ✅ done in Stream A | No refactor needed for the top-level seam. |
| Introduce `KmsClient` port + factory selection by env var (`KMS_PROVIDER=file\|pkcs11\|vault\|aws\|gcp\|azure`) | ⏳ pending | Lands when the first non-file backend is implemented. The file-backed dev path keeps `KMS_PROVIDER=file` as default. |
| `Pkcs11KmsClient` reference implementation | ⏳ pending | Depends on operator choosing an HSM model (YubiHSM 2, Nitrokey HSM 2, Thales Luna USB, Entrust nShield Edge). PKCS#11 is the common contract across vendors. |
| Bootstrap manifest format | ⏳ pending | Likely a small JSON sidecar in `$KEK_MOUNT_DIR/bootstrap.json` pointing at `kms_provider`, `slot_id` / `label`, and `wrapping_key_id`. |
| Zeroise plaintext KEK on shutdown | ⏳ pending | Currently the KEK lives in a `ByteArray` until GC. Adding an explicit zeroise (overwrite + dereference) before process exit closes the post-mortem-memory-dump attack window. |

The TL;DR: the code is already structured so an HSM backend slots in behind the existing
`KekProvider` interface without touching `KekRotationJob`, `DekRotationJob`, or any
application-layer use case.

## 5. Operator runbook — dev

```bash
# 1. Generate the security-service's own material.
security-service/scripts/init-dev-certs.sh

# 2. Issue the monolith its client cert + ship it to scaffold/secrets/.
security-service/scripts/init-dev-certs.sh --export-monolith-client-to ../scaffold/secrets

# 3. Configure security-service/.env (paths are inside this service's own tree).
# See .env.example for the full list; cert-relevant lines are:
#   SECURITY_SERVICE_KEYSTORE_PATH=./secrets/keystore.p12
#   SECURITY_SERVICE_KEYSTORE_PASSWORD=devpass
#   SECURITY_SERVICE_KEYSTORE_ALIAS=security-service
#   SECURITY_SERVICE_TRUSTSTORE_PATH=./secrets/truststore.p12
#   SECURITY_SERVICE_TRUSTSTORE_PASSWORD=devpass
#   KEK_MOUNT_DIR=./secrets
#   AUDIT_HMAC_KEY=$(cat ./secrets/audit_hmac_key)

# 4. Configure scaffold/.env (paths are inside the monolith's own tree).
#   SECURITY_SERVICE_URL=https://localhost:8443
#   SECURITY_SERVICE_CLIENT_CERT_PATH=./secrets/monolith-client.pem
#   SECURITY_SERVICE_CLIENT_KEY_PATH=./secrets/monolith-client.key
#   SECURITY_SERVICE_CA_PATH=./secrets/ca.pem

# 5. Validate before booting the monolith.
curl --cacert security-service/secrets/ca.pem \
     --cert  security-service/secrets/monolith-client.pem \
     --key   security-service/secrets/monolith-client.key \
     https://localhost:8443/v1/health
# expect: 200 OK with {"status":"UP"}
```

The script is idempotent. Re-running it without `--force` is a no-op for any file that
already exists; pass `--force` to regenerate everything (which invalidates every cert
ever issued — every consuming service needs its export step re-run).

## 6. Operator runbook — prod (HSM-rooted)

Detailed runbook lives in the future `docs/PRODUCTION_DEPLOYMENT.md`. Headline sequence:

1. **Provision the HSM.** Choose a hardware token model (YubiHSM 2, Nitrokey HSM 2,
   Thales Luna USB, Entrust nShield Edge — anything with a working PKCS#11 driver).
   Initialise from an offline workstation; record the unlock PIN under multi-person
   quorum control.
2. **Generate the root CA on the HSM.** Use `step certificate create --kms pkcs11:...
   --profile root-ca` so the private key never exists as bytes outside the device.
   Export only the public cert (`root.crt`).
3. **Generate the Linkerd identity issuer.** `step certificate sign` against the HSM-held
   root, producing `issuer.crt` + `issuer.key`. The issuer key is *cluster-resident* (a
   k8s Secret) — it is the rotation-pivot, not the root.
4. **Install Linkerd** pointing at the HSM-rooted material:
   ```bash
   linkerd install \
       --identity-trust-anchors-file root.crt \
       --identity-issuer-certificate-file issuer.crt \
       --identity-issuer-key-file issuer.key
   ```
5. **Annotate the namespace** `linkerd.io/inject: enabled` so security-service pods are
   mTLS'd by sidecar automatically. No `keystore.p12` files in prod.
6. **Mount the HSM-wrapped KEK** at `$KEK_MOUNT_DIR`. The KEK does NOT come from
   Linkerd — it is a separate trust authority (§1 row 3). Wrapping is performed once,
   off-cluster, by an operator session with HSM access.
7. **Set the KMS bootstrap env vars** so `HsmUnwrappingKekProvider` knows where to find
   its PKCS#11 driver and which HSM slot to use. (Exact env-var contract lands when the
   prod KMS provider is implemented — see §4.)
8. **Do not run `init-dev-certs.sh` in prod.** It generates a self-signed CA as a file on
   disk, which is a development convenience and an audit finding in production.

### 6.1 Quorum and physical custody

The root CA's PIN should be split via Shamir's Secret Sharing (e.g. 3-of-5) across
operators with no single-point physical access. Issuer-rotation ceremonies require a
quorum to unlock the HSM. The HSM itself lives in a tamper-evident container in a safe;
its location is recorded in operational documentation that lives off-cluster.

This is heavy-handed for a small team. The lighter alternative is a single operator with
a single HSM in personal physical custody — acceptable for early-stage deployments where
the bus-factor risk is "we lose the HSM and have to re-issue every cert", which is
recoverable (workload certs auto-rotate; the worst case is a 24-h re-issuance window).

The right ceremony depends on your threat model. The architecture supports both.
