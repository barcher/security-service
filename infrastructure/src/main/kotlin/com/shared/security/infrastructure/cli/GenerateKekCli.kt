package com.shared.security.infrastructure.cli

import com.shared.security.adapters.outbound.crypto.MlKemCryptoKeyService
import java.security.MessageDigest
import java.util.Base64

/**
 * Bootstrap CLI: mints a fresh ML-KEM-768 keypair and prints it to stdout. Used to
 * provision the **first** current KEK (or to rebuild from disaster). No security-service
 * instance need be running; the CLI is a pure local computation over the BouncyCastle
 * ML-KEM-768 generator.
 *
 * **NOT for rotation.** Once a current KEK is in place, all subsequent rotations go
 * through `POST /v1/admin/rotate-kek` — that path is gated by mTLS + the admin
 * allowlist, writes an audit event, and feeds the STAGED → ACTIVE → PRIOR lifecycle.
 * This CLI bypasses all of that intentionally because at bootstrap there is no admin
 * cert chain to authenticate against and no live `MlKemCryptoKeyService` to call.
 *
 * Usage:
 *
 * ```
 * # From security-service/
 * ./gradlew :infrastructure:run --args="generate-kek"
 *
 * # Or against the built jar
 * java -jar infrastructure/build/libs/infrastructure-all.jar generate-kek
 * ```
 *
 * Output is two `KEY=VALUE` lines suitable for direct paste into
 * `security-service/.env`:
 *
 * ```
 * ML_KEM_PUBLIC_KEY_CURRENT=<base64>
 * ML_KEM_PRIVATE_KEY_CURRENT=<base64>
 * ```
 *
 * The fingerprint of the public key is printed to stderr so the operator can record it
 * out-of-band (paper / vault / runbook) for later attestation against `/v1/admin/key-status`.
 *
 * **Operator responsibilities after running:**
 *
 *  1. Paste both lines into `security-service/.env` (replacing any blank
 *     `ML_KEM_*_CURRENT` placeholders).
 *  2. In prod, install the private key under the file-mount / HSM and store the env-var
 *     form only as a recovery copy.
 *  3. Restart the security service; verify startup log shows `current=loaded`.
 *  4. Record the printed fingerprint somewhere the audit trail can reference.
 *  5. From the monolith, run `rewrapAllDeksForNewKek(newPublicKeyBytes)` to migrate
 *     legacy-tagged DEK rows under the new current KEK.
 */
class GenerateKekCli {
    fun run(args: List<String> = emptyList()) {
        val force = args.contains("--force")
        gateAgainstMisuse(force = force)
        emitWarningBanner(force = force)

        val pair = MlKemCryptoKeyService.generateBootstrapKekPair()
        val publicKeyB64 = pair.publicKeyB64
        val privateKeyB64 = pair.privateKeyB64
        val publicKeyBytes = Base64.getDecoder().decode(publicKeyB64)
        val fingerprint = sha256ColonHex(publicKeyBytes)

        // stderr: human-readable, suitable for operator runbook capture.
        System.err.println(
            buildString {
                appendLine("generate-kek: minted fresh ML-KEM-768 keypair.")
                appendLine("  algorithm:   ML-KEM-768 (FIPS 203)")
                appendLine("  fingerprint: $fingerprint   (SHA-256 of public key, colon-hex)")
                appendLine("  public bytes: ${publicKeyBytes.size}")
                appendLine()
                appendLine("Paste the two KEY=VALUE lines below into security-service/.env, restart, then")
                appendLine("confirm `current=loaded` in the startup log. Record the fingerprint out-of-band.")
            },
        )

        // stdout: machine-readable env-var lines for direct shell piping / .env paste.
        println("ML_KEM_PUBLIC_KEY_CURRENT=$publicKeyB64")
        println("ML_KEM_PRIVATE_KEY_CURRENT=$privateKeyB64")
    }

    /**
     * Refuse to run when a current KEK is already configured — the only reasons to mint
     * a NEW bootstrap keypair after the first one are (a) disaster recovery and (b)
     * operator error. `--force` overrides the gate for case (a); case (b) is what the
     * gate prevents. In-band rotation MUST go through `POST /v1/admin/rotate-kek`
     * (mTLS + admin allowlist + audit event + lifecycle row transitions).
     */
    private fun gateAgainstMisuse(force: Boolean) {
        val currentPub = System.getenv("ML_KEM_PUBLIC_KEY_CURRENT")?.takeIf { it.isNotBlank() }
        val currentPriv = System.getenv("ML_KEM_PRIVATE_KEY_CURRENT")?.takeIf { it.isNotBlank() }
        if (currentPub == null && currentPriv == null) return
        if (force) {
            System.err.println(
                "generate-kek: WARNING --force overrides the safety gate. A current KEK is " +
                    "already configured; minting a new bootstrap keypair will REPLACE it. " +
                    "Existing DEKs wrapped under the old current KEK will be unreadable until " +
                    "either the old KEK material is preserved or rewrapAllDeksForNewKek is run.",
            )
            return
        }
        System.err.println(
            buildString {
                appendLine("generate-kek: REFUSING to run — a current KEK is already configured.")
                appendLine()
                appendLine("  ML_KEM_PUBLIC_KEY_CURRENT  is " + if (currentPub != null) "SET" else "blank")
                appendLine("  ML_KEM_PRIVATE_KEY_CURRENT is " + if (currentPriv != null) "SET" else "blank")
                appendLine()
                appendLine("This CLI is BOOTSTRAP ONLY. For in-band rotation use the admin route")
                appendLine("instead — it is gated by mTLS + the admin allowlist, emits a KEK_ROTATED")
                appendLine("audit event, and flows into the STAGED → ACTIVE → PRIOR lifecycle:")
                appendLine()
                appendLine("  curl -sS -k --cert <admin-cert.pem> --key <admin-key.pem> \\")
                appendLine("       -X POST https://localhost:8443/v1/admin/rotate-kek")
                appendLine()
                appendLine("If you genuinely need to override (disaster recovery, no surviving")
                appendLine("current KEK material), re-run with --force. See KEK_LIFECYCLE.md.")
            },
        )
        kotlin.system.exitProcess(2)
    }

    private fun emitWarningBanner(force: Boolean) {
        val banner =
            if (force) {
                "FORCED BOOTSTRAP — replacing existing current KEK. See KEK_LIFECYCLE.md."
            } else {
                "BOOTSTRAP ONLY — first-time KEK provisioning. For rotation use POST /v1/admin/rotate-kek."
            }
        val bar = "=".repeat(banner.length + 4)
        System.err.println()
        System.err.println(bar)
        System.err.println("! $banner !")
        System.err.println(bar)
        System.err.println()
    }

    private fun sha256ColonHex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString(":") { "%02x".format(it) }
}
