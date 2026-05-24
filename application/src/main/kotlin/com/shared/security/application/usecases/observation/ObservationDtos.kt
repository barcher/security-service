package com.shared.security.application.usecases.observation

import kotlinx.datetime.Instant

/**
 * Stream L L.0 — lifecycle-metadata-only projections of the security service's
 * persistent state. The observability surface exposes these instead of the raw
 * repository records so encrypted material, key bytes, and audit-chain HMACs are
 * structurally absent from the wire (proposal §6).
 *
 * Each DTO contains only the fields that an operator dashboard legitimately needs:
 * identity, lifecycle status, timestamps. Nothing that could be used to forge a
 * signature, unwrap a DEK, or rewrite the audit chain.
 */
data class KekObservation(
    val id: String,
    val fingerprint: String,
    val status: String,
    val createdAt: Instant,
    val activatedAt: Instant?,
    val quiescedAt: Instant?,
    val retiredAt: Instant?,
)

data class DekObservation(
    val handleHex: String,
    val kekId: String,
    val createdAt: Instant,
    val updatedAt: Instant,
)

data class DekObservationPage(
    val items: List<DekObservation>,
    val totalCount: Long,
)

data class JwtSigningKeyObservation(
    val kidHex: String,
    val status: String,
    val algorithm: String,
    val curve: String,
    val wrappedUnderKekId: String,
    val createdAt: Instant,
    val activatedAt: Instant?,
    val quiescedAt: Instant?,
    val retiredAt: Instant?,
    val retainUntil: Instant?,
)

data class AuditObservation(
    val id: Long,
    val occurredAt: Instant,
    val eventType: String,
    val actorSubject: String?,
    val kekId: String?,
    val dekHandleHex: String?,
    val success: Boolean,
    val detailJson: String?,
)

data class AuditObservationPage(
    val items: List<AuditObservation>,
    val totalCount: Long,
    val page: Int,
    val pageSize: Int,
)

data class RotationObservation(
    val id: Long,
    val occurredAt: Instant,
    val eventType: String,
    val actorSubject: String?,
    val kekId: String?,
    val detailJson: String?,
)
