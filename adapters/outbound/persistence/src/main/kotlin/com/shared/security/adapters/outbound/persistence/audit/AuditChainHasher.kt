package com.shared.security.adapters.outbound.persistence.audit

import com.shared.security.application.ports.AuditEvent
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Computes the HMAC-SHA-512 row hash for the audit chain.
 *
 * The chain is defined as:
 *
 *     row_hmac[n] = HMAC-SHA-512(AUDIT_HMAC_KEY, canonical_payload[n] || prev_hmac[n])
 *     prev_hmac[n] = row_hmac[n - 1]  (zero-byte sentinel for n = 1)
 *
 * `canonical_payload[n]` is a deterministic byte encoding of every field in [AuditEvent]
 * except `prev_hmac` / `row_hmac` (those are the chain bytes themselves; including them
 * would create a self-reference). The encoding is:
 *
 *     occurred_at_epoch_millis (8 bytes BE)
 *   ‖ event_type_len (4 bytes BE) ‖ event_type (UTF-8 bytes)
 *   ‖ actor_subject_present (1 byte) [‖ subject_len (4 BE) ‖ subject_utf8]
 *   ‖ dek_handle_present (1 byte)    [‖ handle_len (4 BE)  ‖ handle_bytes]
 *   ‖ kek_id_present (1 byte)        [‖ kek_id_len (4 BE)  ‖ kek_id_utf8]
 *   ‖ success (1 byte: 0x01 / 0x00)
 *   ‖ detail_present (1 byte)        [‖ detail_len (4 BE)  ‖ detail_utf8]
 *
 * This is intentionally NOT JSON: any whitespace/ordering ambiguity in JSON would let two
 * payloads with the same logical content produce different HMACs, which makes the chain
 * verifier unreliable. Length-prefixed framing avoids that.
 *
 * The hash key is held in memory only — `AUDIT_HMAC_KEY` env var is read once at startup by
 * [AuditHmacKeyProvider]. It is independent of any KEK (per proposal §10) so leaking one
 * does not compromise the other.
 */
class AuditChainHasher(private val hmacKey: ByteArray) {
    init {
        require(hmacKey.size >= MIN_KEY_BYTES) {
            "AUDIT_HMAC_KEY must be at least $MIN_KEY_BYTES bytes; got ${hmacKey.size}"
        }
    }

    fun hash(
        event: AuditEvent,
        prevHmac: ByteArray,
    ): ByteArray {
        require(prevHmac.size == HASH_BYTES) {
            "prevHmac must be exactly $HASH_BYTES bytes; got ${prevHmac.size}"
        }
        val payload = canonicalPayload(event)
        val mac = Mac.getInstance(HMAC_ALG)
        mac.init(SecretKeySpec(hmacKey, HMAC_ALG))
        mac.update(payload)
        mac.update(prevHmac)
        return mac.doFinal()
    }

    @Suppress("LongMethod") // explicit framing for every field is the safer pattern
    fun canonicalPayload(event: AuditEvent): ByteArray {
        val typeBytes = event.eventType.toByteArray(StandardCharsets.UTF_8)
        val subjectBytes = event.actorSubject?.toByteArray(StandardCharsets.UTF_8)
        val kekIdBytes = event.kekId?.toByteArray(StandardCharsets.UTF_8)
        val detailBytes = event.detailJson?.toByteArray(StandardCharsets.UTF_8)
        val totalLen =
            INT_LEN + typeBytes.size +
                INT_LEN +
                BYTE_LEN + (subjectBytes?.size?.let { INT_LEN + it } ?: 0) +
                BYTE_LEN + (event.dekHandle?.size?.let { INT_LEN + it } ?: 0) +
                BYTE_LEN + (kekIdBytes?.size?.let { INT_LEN + it } ?: 0) +
                BYTE_LEN +
                BYTE_LEN + (detailBytes?.size?.let { INT_LEN + it } ?: 0)

        val buf = ByteBuffer.allocate(LONG_LEN + totalLen)
        buf.putLong(event.occurredAt.toEpochMilliseconds())
        putLengthPrefixed(buf, typeBytes)
        putOptional(buf, subjectBytes)
        putOptional(buf, event.dekHandle)
        putOptional(buf, kekIdBytes)
        buf.put(if (event.success) 0x01.toByte() else 0x00.toByte())
        putOptional(buf, detailBytes)
        return buf.array().copyOfRange(0, buf.position())
    }

    private fun putLengthPrefixed(
        buf: ByteBuffer,
        bytes: ByteArray,
    ) {
        buf.putInt(bytes.size)
        buf.put(bytes)
    }

    private fun putOptional(
        buf: ByteBuffer,
        bytes: ByteArray?,
    ) {
        if (bytes == null) {
            buf.put(0x00.toByte())
        } else {
            buf.put(0x01.toByte())
            putLengthPrefixed(buf, bytes)
        }
    }

    companion object {
        /** Length of every HMAC-SHA-512 digest, in bytes. */
        const val HASH_BYTES = 64

        /** Minimum recommended key length (RFC 4868 §2.1.1 — for SHA-512, ≥ 64 bytes). */
        const val MIN_KEY_BYTES = 32

        private const val HMAC_ALG = "HmacSHA512"
        private const val INT_LEN = 4
        private const val LONG_LEN = 8
        private const val BYTE_LEN = 1

        /** Zero-byte sentinel used as prev_hmac for the very first chain row. */
        val INITIAL_PREV_HMAC: ByteArray = ByteArray(HASH_BYTES)
    }
}
