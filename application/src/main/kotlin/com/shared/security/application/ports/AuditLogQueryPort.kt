package com.shared.security.application.ports

import kotlinx.datetime.Instant

/**
 * Stream L L.0 — read-side companion to [AuditLogPort]. The two ports are deliberately
 * split: the write side has a single `write(event)` method gated by the HMAC chain hasher;
 * the read side serves the dashboard observability surface and has no need for chain
 * mutation primitives. Keeping them apart keeps the write contract minimal and means a
 * compromised dashboard observer cannot insert into the chain.
 *
 * Implementations strip `row_hmac` and `prev_hmac` from results before returning —
 * those bytes are useful only inside the persistence module's chain verification logic
 * (`ExposedAuditLogRepository.verifyChain`).
 */
interface AuditLogQueryPort {
    /**
     * Faceted query against `audit_events`. All filters are conjunctive; null means "no
     * filter on that facet". Results are ordered `occurred_at` desc.
     *
     * The page contract uses 0-based indexing. `size` is bounded by the implementation
     * (typical cap: 200 per page) — passing a larger value should clamp rather than
     * throw, so the route layer's validation can decouple from this port's internal cap.
     */
    suspend fun search(
        freeText: String? = null,
        eventTypeIn: Set<String>? = null,
        fromTime: Instant? = null,
        toTime: Instant? = null,
        page: Int,
        size: Int,
    ): SearchResult

    data class Row(
        val id: Long,
        val occurredAt: Instant,
        val eventType: String,
        val actorSubject: String?,
        val kekId: String?,
        val dekHandle: ByteArray?,
        val success: Boolean,
        val detailJson: String?,
    ) {
        override fun equals(other: Any?): Boolean = this === other

        override fun hashCode(): Int = System.identityHashCode(this)
    }

    data class SearchResult(
        val rows: List<Row>,
        val totalCount: Long,
    )
}
