package com.shared.security.adapters.inbound.http.dto

import kotlinx.serialization.Serializable

/**
 * Wire DTOs for the Stream L L.0 observability surface. All fields are plain JSON value
 * types — no binary blobs. The use-case-layer observation DTOs already strip key
 * material; these are just serialization-friendly mirrors.
 */
@Serializable
data class KekObservationDto(
    val id: String,
    val fingerprint: String,
    val status: String,
    val createdAt: String,
    val activatedAt: String? = null,
    val quiescedAt: String? = null,
    val retiredAt: String? = null,
)

@Serializable
data class ListKeksResponse(val keks: List<KekObservationDto>)

@Serializable
data class DekObservationDto(
    val handleHex: String,
    val kekId: String,
    val createdAt: String,
    val updatedAt: String,
)

@Serializable
data class ListDeksResponse(
    val deks: List<DekObservationDto>,
    val totalCount: Long,
)

@Serializable
data class JwtSigningKeyObservationDto(
    val kidHex: String,
    val status: String,
    val algorithm: String,
    val curve: String,
    val wrappedUnderKekId: String,
    val createdAt: String,
    val activatedAt: String? = null,
    val quiescedAt: String? = null,
    val retiredAt: String? = null,
    val retainUntil: String? = null,
)

@Serializable
data class ListJwtSigningKeysResponse(val keys: List<JwtSigningKeyObservationDto>)

@Serializable
data class AuditObservationDto(
    val id: Long,
    val occurredAt: String,
    val eventType: String,
    val actorSubject: String? = null,
    val kekId: String? = null,
    val dekHandleHex: String? = null,
    val success: Boolean,
    val detailJson: String? = null,
)

@Serializable
data class SearchAuditEventsResponse(
    val items: List<AuditObservationDto>,
    val totalCount: Long,
    val page: Int,
    val pageSize: Int,
)

@Serializable
data class RotationObservationDto(
    val id: Long,
    val occurredAt: String,
    val eventType: String,
    val actorSubject: String? = null,
    val kekId: String? = null,
    val detailJson: String? = null,
)

@Serializable
data class ListRecentRotationsResponse(val rotations: List<RotationObservationDto>)
