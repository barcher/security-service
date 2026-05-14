package com.shared.security.application.usecases

import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.CryptoKeyServicePort
import com.shared.security.application.ports.DekRecord
import com.shared.security.application.ports.DekRepository
import com.shared.security.application.ports.KekLifecycleStatus
import com.shared.security.application.ports.KekPair
import com.shared.security.application.ports.KekRecord
import com.shared.security.application.ports.KekRepository
import com.shared.security.application.ports.WrappedDek
import kotlinx.datetime.Instant
import java.util.UUID

/**
 * Tiny in-memory fakes for Stream-C use case tests. Each fake records the calls it received
 * so assertions can target either state OR call-sequence (e.g. audit-event ordering).
 */
class RecordingAuditLog : AuditLogPort {
    val events = mutableListOf<AuditEvent>()

    override suspend fun write(event: AuditEvent) {
        events += event
    }
}

/**
 * Crypto fake whose `generateDek`, `unwrapDek`, and `rewrapDekForNewKek` succeed or throw
 * based on the per-method flags. Plaintext bytes returned are deterministic so tests can
 * verify zeroization without a real KEM.
 */
class FlakyCryptoKeyService(
    var failGenerate: Boolean = false,
    var failUnwrap: Boolean = false,
    var failRewrap: Boolean = false,
) : CryptoKeyServicePort {
    override val isAvailable: Boolean = true
    var rewrapCount: Int = 0
        private set

    override suspend fun generateDek(): CryptoKeyServicePort.GeneratedDek {
        if (failGenerate) error("generate failed")
        return CryptoKeyServicePort.GeneratedDek(
            wrapped = WrappedDek(kemCiphertextB64 = "KEM", encryptedDekB64 = "ENC"),
            plaintextBytes = ByteArray(32) { 7 },
        )
    }

    override suspend fun wrapDek(dekBytes: ByteArray): WrappedDek = stubWrapped()

    private fun stubWrapped(): WrappedDek = WrappedDek(kemCiphertextB64 = "KEM", encryptedDekB64 = "ENC")

    override suspend fun unwrapDek(wrapped: WrappedDek): ByteArray {
        if (failUnwrap) error("unwrap failed")
        return ByteArray(32) { 7 }
    }

    override suspend fun rewrapDekForNewKek(
        existingWrapped: WrappedDek,
        newPublicKeyBytes: ByteArray,
    ): WrappedDek {
        if (failRewrap) error("rewrap failed")
        rewrapCount++
        return WrappedDek(kemCiphertextB64 = "KEM-new", encryptedDekB64 = "ENC-new")
    }

    override fun generateNewKekPair(): KekPair = KekPair(publicKeyB64 = "PUB-NEW", privateKeyB64 = "PRIV-NEW")

    override fun getPublicKeyFingerprint(): String = "fp:test"
}

class FakeKekRepository : KekRepository {
    val byId = mutableMapOf<String, KekRecord>()
    val retired = mutableListOf<String>()

    override suspend fun findActive(): KekRecord? = byId.values.firstOrNull { it.status == KekLifecycleStatus.ACTIVE }

    override suspend fun findAllPrior(): List<KekRecord> =
        byId.values.filter { it.status == KekLifecycleStatus.PRIOR }.sortedBy { it.createdAt }

    override suspend fun findById(id: String): KekRecord? = byId[id]

    override suspend fun retirePrior(id: String): Boolean {
        val current = byId[id] ?: return false
        if (current.status != KekLifecycleStatus.PRIOR) return false
        byId[id] = current.copy(status = KekLifecycleStatus.RETIRED, retiredAt = Instant.fromEpochMilliseconds(0))
        retired += id
        return true
    }

    fun seed(
        status: KekLifecycleStatus,
        createdAt: Instant = Instant.fromEpochMilliseconds(0),
        quiescedAt: Instant? = null,
    ): String {
        val id = UUID.randomUUID().toString()
        byId[id] =
            KekRecord(
                id = id,
                fingerprint = "fp:$id",
                status = status,
                createdAt = createdAt,
                activatedAt = if (status != KekLifecycleStatus.STAGED) createdAt else null,
                quiescedAt = quiescedAt,
                retiredAt = null,
            )
        return id
    }
}

class FakeDekRepository : DekRepository {
    val byHandle = mutableMapOf<String, DekRecord>()
    val rewraps = mutableListOf<Triple<String, String, ByteArray>>()

    override suspend fun countByKekId(kekId: String): Long {
        return byHandle.values.count { it.kekId == kekId }.toLong()
    }

    override suspend fun findBatchByKekId(
        kekId: String,
        limit: Int,
    ): List<DekRecord> =
        byHandle.values
            .filter { it.kekId == kekId }
            .sortedBy { it.createdAt }
            .take(limit)

    override suspend fun rewrap(
        handle: ByteArray,
        newKekId: String,
        newWrappedBytes: ByteArray,
        updatedAt: Instant,
    ): Boolean {
        val key = handle.toHex()
        val existing = byHandle[key] ?: return false
        byHandle[key] = existing.copy(kekId = newKekId, wrappedDekBytes = newWrappedBytes, updatedAt = updatedAt)
        rewraps += Triple(key, newKekId, newWrappedBytes)
        return true
    }

    fun seed(
        kekId: String,
        count: Int,
    ) {
        repeat(count) { i ->
            val handle = ByteArray(16) { ((i + 1) * 13).toByte() }
            byHandle[handle.toHex()] =
                DekRecord(
                    handle = handle,
                    kekId = kekId,
                    wrappedDekBytes = "wrapped-$i".toByteArray(),
                    createdAt = Instant.fromEpochMilliseconds(i.toLong()),
                    updatedAt = Instant.fromEpochMilliseconds(i.toLong()),
                )
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
