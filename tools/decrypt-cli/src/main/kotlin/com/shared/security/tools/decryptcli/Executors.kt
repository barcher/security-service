package com.shared.security.tools.decryptcli

import com.shared.security.application.ports.AuditLogQueryPort
import com.shared.security.application.ports.DekRepository
import com.shared.security.application.ports.JwtSigningKeyRepository
import java.util.Base64

/**
 * Phase 14 Stream M (SKS-M12) — per-scope executors for the operator decrypt CLI.
 *
 * Each executor takes a parsed `CliArgs.Scope` and returns a stream of
 * `OperatorDecryptOutput.DecryptedRow` instances. None of them log plaintext
 * (SLF4J calls absent — enforced by ArchUnit S-16).
 *
 * Per `feedback_operator_decrypt_cli_single_sided.md` the executors target
 * security-service-owned ciphertext only:
 *
 *   * [UnwrapDekExecutor] — `--key-handle <hex>` — returns DEK metadata
 *     including the kemCiphertext blob (base64). The CLI does NOT decapsulate
 *     the DEK plaintext in v1.0 because the security-service-internal DEK
 *     storage format (per Stream C) only persists the kemCiphertext; the
 *     paired encrypted-DEK-bytes portion is supplied per-request by the
 *     monolith and never durably stored on the security-service side. Future
 *     ticket M.* may extend this to JWT signing keys via `KekEnvelopePort`.
 *   * [AuditDetailExecutor] — `--audit-event-id <id>` — returns the audit
 *     row's currently-plaintext `detail_json` field. No decryption is
 *     performed today; the executor exists so a future encrypted
 *     `detail_json` (out of scope for Stream M v1.0) drops in cleanly.
 *   * [JwtSigningKeyExecutor] — `--key-handle <hex>` against a JWT signing
 *     key id — returns the wrapped-private-key bytes (base64). Full PEM
 *     unwrap via `KekEnvelopePort` lands in a future ticket; v1.0 emits the
 *     wrapped envelope so an incident responder can save it for offline
 *     forensics.
 */
class UnwrapDekExecutor(private val dekRepository: DekRepository) {
    suspend fun execute(handleHex: String): List<OperatorDecryptOutput.DecryptedRow> {
        val handleBytes = hexToBytes(handleHex)
        val batch = dekRepository.findRecent(BATCH_SIZE)
        val match =
            batch.firstOrNull { it.handle.contentEquals(handleBytes) }
                ?: return emptyList()
        return listOf(
            OperatorDecryptOutput.DecryptedRow(
                table = "security_keys.deks",
                primaryKey = bytesToHex(match.handle),
                dekHandleHex = bytesToHex(match.handle),
                columnDecrypts =
                    mapOf(
                        "kek_id" to match.kekId,
                        "wrapped_dek_bytes_b64" to Base64.getEncoder().encodeToString(match.wrappedDekBytes),
                        "created_at" to match.createdAt.toString(),
                        "updated_at" to match.updatedAt.toString(),
                    ),
            ),
        )
    }

    private companion object {
        private const val BATCH_SIZE = 500
    }
}

class JwtSigningKeyExecutor(private val jwtRepository: JwtSigningKeyRepository) {
    suspend fun execute(kidHex: String): List<OperatorDecryptOutput.DecryptedRow> {
        val kidBytes = hexToBytes(kidHex)
        val record = jwtRepository.findByKid(kidBytes) ?: return emptyList()
        return listOf(
            OperatorDecryptOutput.DecryptedRow(
                table = "security_keys.jwt_signing_keys",
                primaryKey = bytesToHex(record.kid),
                keyHandle = bytesToHex(record.kid),
                columnDecrypts =
                    mapOf(
                        "status" to record.status.name,
                        "algorithm" to record.algorithm,
                        "curve" to record.curve,
                        "wrapped_under_kek_id" to record.wrappedUnderKekId,
                        "wrapped_private_key_bytes_b64" to
                            Base64.getEncoder().encodeToString(record.wrappedPrivateKeyBytes),
                        "public_key_spki_b64" to
                            Base64.getEncoder().encodeToString(record.publicKeySpki),
                        "created_at" to record.createdAt.toString(),
                    ),
            ),
        )
    }
}

class AuditDetailExecutor(private val auditLogQuery: AuditLogQueryPort) {
    suspend fun execute(auditEventId: Long): List<OperatorDecryptOutput.DecryptedRow> {
        val record = auditLogQuery.findById(auditEventId) ?: return emptyList()
        return listOf(record.toRow())
    }

    private fun AuditLogQueryPort.Row.toRow(): OperatorDecryptOutput.DecryptedRow =
        OperatorDecryptOutput.DecryptedRow(
            table = "security_keys.audit_events",
            primaryKey = id.toString(),
            columnDecrypts =
                mapOf(
                    "occurred_at" to occurredAt.toString(),
                    "event_type" to eventType,
                    "actor_subject" to actorSubject.orEmpty(),
                    "success" to success.toString(),
                    "detail_json" to detailJson.orEmpty(),
                ),
        )
}

internal fun hexToBytes(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "hex string must have even length, got ${hex.length}" }
    require(hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) { "hex string has non-hex chars" }
    return ByteArray(hex.length / 2) { i ->
        (
            (Character.digit(hex[i * 2], HEX_BASE) shl HEX_NIBBLE_BITS) +
                Character.digit(hex[i * 2 + 1], HEX_BASE)
        ).toByte()
    }
}

internal fun bytesToHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

private const val HEX_BASE = 16
private const val HEX_NIBBLE_BITS = 4
