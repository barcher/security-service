package com.shared.security.adapters.outbound.persistence.audit

import com.shared.security.application.ports.AuditEvent
import kotlinx.datetime.Instant
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AuditChainHasherTest {
    private val key = ByteArray(64) { (it + 1).toByte() }
    private val hasher = AuditChainHasher(key)
    private val prev = ByteArray(64) { 0x00.toByte() }

    private fun event(
        eventType: String = "TEST_EVENT",
        actorSubject: String? = "CN=test",
        dekHandle: ByteArray? = null,
        success: Boolean = true,
        detailJson: String? = null,
    ) = AuditEvent(
        occurredAt = Instant.fromEpochMilliseconds(1_000_000),
        eventType = eventType,
        actorSubject = actorSubject,
        dekHandle = dekHandle,
        kekId = null,
        success = success,
        detailJson = detailJson,
    )

    @Test
    fun `hash is deterministic for the same input`() {
        val a = hasher.hash(event(), prev)
        val b = hasher.hash(event(), prev)

        assertEquals(AuditChainHasher.HASH_BYTES, a.size)
        assertTrue(a.contentEquals(b))
    }

    @Test
    fun `hash changes when occurredAt changes`() {
        val a = hasher.hash(event(), prev)
        val b =
            hasher.hash(
                AuditEvent(
                    occurredAt = Instant.fromEpochMilliseconds(2_000_000),
                    eventType = "TEST_EVENT",
                    actorSubject = "CN=test",
                    success = true,
                ),
                prev,
            )

        assertFalse(a.contentEquals(b))
    }

    @Test
    fun `hash changes when event_type changes`() {
        val a = hasher.hash(event(eventType = "A"), prev)
        val b = hasher.hash(event(eventType = "B"), prev)
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun `hash changes when actor_subject changes`() {
        val a = hasher.hash(event(actorSubject = "CN=alice"), prev)
        val b = hasher.hash(event(actorSubject = "CN=bob"), prev)
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun `null vs empty string actor_subject produce different hashes`() {
        val a = hasher.hash(event(actorSubject = null), prev)
        val b = hasher.hash(event(actorSubject = ""), prev)
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun `hash changes when success flag flips`() {
        val a = hasher.hash(event(success = true), prev)
        val b = hasher.hash(event(success = false), prev)
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun `hash changes when dek_handle changes`() {
        val a = hasher.hash(event(dekHandle = ByteArray(16) { 0x42.toByte() }), prev)
        val b = hasher.hash(event(dekHandle = ByteArray(16) { 0x43.toByte() }), prev)
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun `hash changes when detail_json differs by even one byte`() {
        val a = hasher.hash(event(detailJson = """{"x":1}"""), prev)
        val b = hasher.hash(event(detailJson = """{"x":2}"""), prev)
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun `hash changes when prev_hmac changes`() {
        val a = hasher.hash(event(), prev)
        val b = hasher.hash(event(), ByteArray(64) { 0x99.toByte() })
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun `different keys produce different hashes for the same event`() {
        val key2 = ByteArray(64) { (it + 99).toByte() }
        val hasher2 = AuditChainHasher(key2)

        val a = hasher.hash(event(), prev)
        val b = hasher2.hash(event(), prev)
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun `constructor rejects key shorter than 32 bytes`() {
        assertThrows(IllegalArgumentException::class.java) {
            AuditChainHasher(ByteArray(16))
        }
    }

    @Test
    fun `hash rejects prev_hmac with wrong length`() {
        assertThrows(IllegalArgumentException::class.java) {
            hasher.hash(event(), ByteArray(32))
        }
    }
}
