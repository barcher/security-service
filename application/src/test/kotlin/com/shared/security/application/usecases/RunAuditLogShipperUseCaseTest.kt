package com.shared.security.application.usecases

import com.shared.security.application.ports.AuditBatch
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.ColdStoragePort
import com.shared.security.application.ports.ShipResult
import com.shared.security.application.usecases.RunAuditLogShipperUseCase.ChainVerification
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RunAuditLogShipperUseCaseTest {
    private fun batchOf(
        from: Long,
        to: Long,
    ) = AuditBatch(batchId = "b-$from-$to", fromRowId = from, toRowId = to, bytesCanonical = ByteArray(8))

    @Test
    fun `Ok ship advances last shipped id and writes AUDIT_SHIPPED audit`() =
        runTest {
            val audit = RecordingAuditLog()
            var savedLastId = 0L
            val useCase =
                RunAuditLogShipperUseCase(
                    chainVerifier = { _, _ -> ChainVerification.Ok },
                    batchReader = { from, _ -> batchOf(from, from + 9) },
                    coldStorage = ColdStoragePort { ShipResult.Ok(remoteObjectKey = "s3://b/$it") },
                    auditLog = audit,
                    lastShippedIdProvider = { 0L },
                    lastShippedIdSaver = { savedLastId = it },
                    maxRowsPerBatch = 10,
                )

            val summary = useCase.execute()

            assertTrue(summary is RunAuditLogShipperUseCase.Summary.Shipped)
            val shipped = summary as RunAuditLogShipperUseCase.Summary.Shipped
            assertEquals(1L, shipped.fromRowId)
            assertEquals(10L, shipped.toRowId)
            assertEquals(10L, savedLastId)
            assertTrue(audit.events.any { it.eventType == AuditEventType.AUDIT_SHIPPED && it.success })
        }

    @Test
    fun `Broken chain writes AUDIT_CHAIN_BREAK and does NOT ship`() =
        runTest {
            val audit = RecordingAuditLog()
            var shipCalled = false
            val useCase =
                RunAuditLogShipperUseCase(
                    chainVerifier = { _, _ -> ChainVerification.Broken(firstBadId = 42) },
                    batchReader = { from, _ -> batchOf(from, from) },
                    coldStorage =
                        ColdStoragePort {
                            shipCalled = true
                            ShipResult.Ok("ignored")
                        },
                    auditLog = audit,
                    lastShippedIdProvider = { 0L },
                    lastShippedIdSaver = { },
                )

            val summary = useCase.execute()

            assertTrue(summary is RunAuditLogShipperUseCase.Summary.ChainBroken)
            assertEquals(false, shipCalled)
            val ev = audit.events.firstOrNull { it.eventType == AuditEventType.AUDIT_CHAIN_BREAK }
            assertNotNull(ev)
            assertTrue(ev!!.detailJson!!.contains("\"firstBadId\":42"))
        }

    @Test
    fun `Empty chain yields NothingToShip with no audit`() =
        runTest {
            val audit = RecordingAuditLog()
            val useCase =
                RunAuditLogShipperUseCase(
                    chainVerifier = { _, _ -> ChainVerification.Empty },
                    batchReader = { _, _ -> batchOf(1, 0) },
                    coldStorage = ColdStoragePort { ShipResult.Ok("ignored") },
                    auditLog = audit,
                    lastShippedIdProvider = { 0L },
                    lastShippedIdSaver = { },
                )

            assertEquals(RunAuditLogShipperUseCase.Summary.NothingToShip, useCase.execute())
            assertEquals(0, audit.events.size)
        }

    @Test
    fun `TransientFailure does not advance last shipped id and writes no audit`() =
        runTest {
            val audit = RecordingAuditLog()
            var savedLastId = 0L
            val useCase =
                RunAuditLogShipperUseCase(
                    chainVerifier = { _, _ -> ChainVerification.Ok },
                    batchReader = { from, _ -> batchOf(from, from + 4) },
                    coldStorage = ColdStoragePort { ShipResult.TransientFailure("s3 throttled") },
                    auditLog = audit,
                    lastShippedIdProvider = { 0L },
                    lastShippedIdSaver = { savedLastId = it },
                )

            val summary = useCase.execute()

            assertTrue(summary is RunAuditLogShipperUseCase.Summary.TransientFailure)
            assertEquals(0L, savedLastId)
            assertEquals(0, audit.events.size)
        }

    @Test
    fun `PermanentFailure writes AUDIT_SHIPPED with success=false`() =
        runTest {
            val audit = RecordingAuditLog()
            val useCase =
                RunAuditLogShipperUseCase(
                    chainVerifier = { _, _ -> ChainVerification.Ok },
                    batchReader = { from, _ -> batchOf(from, from + 4) },
                    coldStorage = ColdStoragePort { ShipResult.PermanentFailure("creds revoked") },
                    auditLog = audit,
                    lastShippedIdProvider = { 0L },
                    lastShippedIdSaver = { },
                )

            useCase.execute()

            val ev = audit.events.firstOrNull { it.eventType == AuditEventType.AUDIT_SHIPPED }
            assertNotNull(ev)
            assertEquals(false, ev!!.success)
            assertTrue(ev.detailJson!!.contains("permanent_failure"))
        }
}
