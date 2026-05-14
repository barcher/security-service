package com.shared.security.infrastructure.audit

import com.shared.security.application.ports.AuditBatch
import com.shared.security.application.ports.ColdStoragePort
import com.shared.security.application.ports.ShipResult
import org.slf4j.LoggerFactory

/**
 * Stream-C placeholder for cold-storage shipping. Logs the batch metadata at INFO and
 * returns a synthetic `Ok` result without writing anywhere. The real S3/R2 adapter is
 * wired in Stream E once the cold-storage vendor is selected. The use case path is
 * exercised end-to-end (verify chain → ship → record `lastShippedId`) but no bytes leave
 * the process.
 */
class NoOpColdStorageAdapter : ColdStoragePort {
    private val logger = LoggerFactory.getLogger(NoOpColdStorageAdapter::class.java)

    override suspend fun ship(batch: AuditBatch): ShipResult {
        logger.info(
            "NoOpColdStorageAdapter.ship: batchId={} rows {}..{} ({} bytes) — NOT actually shipped",
            batch.batchId,
            batch.fromRowId,
            batch.toRowId,
            batch.bytesCanonical.size,
        )
        return ShipResult.Ok(remoteObjectKey = "noop:${batch.batchId}")
    }
}
