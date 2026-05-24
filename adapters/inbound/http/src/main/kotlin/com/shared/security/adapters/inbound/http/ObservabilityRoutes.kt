package com.shared.security.adapters.inbound.http

import com.shared.security.adapters.inbound.http.auth.clientPrincipal
import com.shared.security.adapters.inbound.http.dto.AuditObservationDto
import com.shared.security.adapters.inbound.http.dto.DekObservationDto
import com.shared.security.adapters.inbound.http.dto.ErrorResponse
import com.shared.security.adapters.inbound.http.dto.JwtSigningKeyObservationDto
import com.shared.security.adapters.inbound.http.dto.KekObservationDto
import com.shared.security.adapters.inbound.http.dto.ListDeksResponse
import com.shared.security.adapters.inbound.http.dto.ListJwtSigningKeysResponse
import com.shared.security.adapters.inbound.http.dto.ListKeksResponse
import com.shared.security.adapters.inbound.http.dto.ListRecentRotationsResponse
import com.shared.security.adapters.inbound.http.dto.RotationObservationDto
import com.shared.security.adapters.inbound.http.dto.SearchAuditEventsResponse
import com.shared.security.adapters.inbound.http.ratelimit.PerSubjectRateLimiter
import com.shared.security.application.ports.AuditEvent
import com.shared.security.application.ports.AuditEventType
import com.shared.security.application.ports.AuditLogPort
import com.shared.security.application.ports.DashboardObserverAllowList
import com.shared.security.application.usecases.observation.AuditObservation
import com.shared.security.application.usecases.observation.DekObservation
import com.shared.security.application.usecases.observation.JwtSigningKeyObservation
import com.shared.security.application.usecases.observation.KekObservation
import com.shared.security.application.usecases.observation.ListDeksObservationUseCase
import com.shared.security.application.usecases.observation.ListJwtSigningKeysObservationUseCase
import com.shared.security.application.usecases.observation.ListKeksObservationUseCase
import com.shared.security.application.usecases.observation.ListRecentRotationsObservationUseCase
import com.shared.security.application.usecases.observation.RotationObservation
import com.shared.security.application.usecases.observation.SearchAuditEventsObservationUseCase
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respond
import io.ktor.server.routing.Routing
import io.ktor.server.routing.get
import io.ktor.server.routing.route
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

/**
 * Stream L L.0 (SKS-L08) — read-only observability surface under `/v1/observability/`.
 *
 * Every endpoint:
 *
 *   1. Requires an mTLS-authenticated principal (route-layer guarantee via `MtlsAuthPlugin`).
 *   2. Gates on [DashboardObserverAllowList] — the four-lane subject-DN model means the
 *      operational monolith DN + admin DN + operator-decrypt DN all bounce off this
 *      surface with 403 + `OBSERVER_FORBIDDEN` audit.
 *   3. Applies the per-subject rate limit (configurable via `SECURITY_OBSERVABILITY_RATE_LIMIT_*`).
 *   4. Delegates to the matching use case; each use case writes ONE `DASHBOARD_OBSERVED`
 *      audit row per call regardless of result-set size.
 *
 * Errors are uniform via [ErrorResponse]. A 500 path writes an `OBSERVABILITY_ERROR`
 * audit row before responding so operator forensics has a chain entry for every failure.
 */
fun Routing.installObservabilityRoutes(
    observerAllowList: DashboardObserverAllowList,
    auditLog: AuditLogPort,
    rateLimiter: PerSubjectRateLimiter? = null,
    listKeks: ListKeksObservationUseCase,
    listDeks: ListDeksObservationUseCase,
    listJwtSigningKeys: ListJwtSigningKeysObservationUseCase,
    searchAuditEvents: SearchAuditEventsObservationUseCase,
    listRecentRotations: ListRecentRotationsObservationUseCase,
) {
    route("/v1/observability") {
        get("/keks") {
            handle(observerAllowList, auditLog, rateLimiter, endpoint = "/v1/observability/keks") { subject ->
                val data = listKeks.execute(actorSubject = subject)
                call.respond(
                    HttpStatusCode.OK,
                    ListKeksResponse(keks = data.map { it.toDto() }),
                )
            }
        }

        get("/deks") {
            handle(observerAllowList, auditLog, rateLimiter, endpoint = "/v1/observability/deks") { subject ->
                val limit = call.intParam("limit") ?: ListDeksObservationUseCase.DEFAULT_LIMIT
                val page = listDeks.execute(actorSubject = subject, limit = limit)
                call.respond(
                    HttpStatusCode.OK,
                    ListDeksResponse(
                        deks = page.items.map { it.toDto() },
                        totalCount = page.totalCount,
                    ),
                )
            }
        }

        get("/jwt-signing-keys") {
            handle(
                observerAllowList,
                auditLog,
                rateLimiter,
                endpoint = "/v1/observability/jwt-signing-keys",
            ) { subject ->
                val data = listJwtSigningKeys.execute(actorSubject = subject)
                call.respond(
                    HttpStatusCode.OK,
                    ListJwtSigningKeysResponse(keys = data.map { it.toDto() }),
                )
            }
        }

        get("/audit-events") {
            handle(observerAllowList, auditLog, rateLimiter, endpoint = "/v1/observability/audit-events") { subject ->
                val freeText = call.request.queryParameters["q"]?.takeIf { it.isNotBlank() }
                val eventTypeIn =
                    call.request.queryParameters["eventTypeFilter"]
                        ?.split(',')
                        ?.map { it.trim() }
                        ?.filter { it.isNotEmpty() }
                        ?.toSet()
                val fromTime = call.instantParam("fromIso")
                val toTime = call.instantParam("toIso")
                val page = call.intParam("page") ?: 0
                val size = call.intParam("size") ?: SearchAuditEventsObservationUseCase.DEFAULT_PAGE_SIZE

                val result =
                    searchAuditEvents.execute(
                        actorSubject = subject,
                        freeText = freeText,
                        eventTypeIn = eventTypeIn,
                        fromTime = fromTime,
                        toTime = toTime,
                        page = page,
                        size = size,
                    )
                call.respond(
                    HttpStatusCode.OK,
                    SearchAuditEventsResponse(
                        items = result.items.map { it.toDto() },
                        totalCount = result.totalCount,
                        page = result.page,
                        pageSize = result.pageSize,
                    ),
                )
            }
        }

        get("/recent-rotations") {
            handle(
                observerAllowList,
                auditLog,
                rateLimiter,
                endpoint = "/v1/observability/recent-rotations",
            ) { subject ->
                val n = call.intParam("n") ?: ListRecentRotationsObservationUseCase.DEFAULT_N
                val data = listRecentRotations.execute(actorSubject = subject, n = n)
                call.respond(
                    HttpStatusCode.OK,
                    ListRecentRotationsResponse(rotations = data.map { it.toDto() }),
                )
            }
        }
    }
}

private suspend fun io.ktor.server.routing.RoutingContext.handle(
    observerAllowList: DashboardObserverAllowList,
    auditLog: AuditLogPort,
    rateLimiter: PerSubjectRateLimiter?,
    endpoint: String,
    block: suspend (subject: String) -> Unit,
) {
    val principal =
        call.clientPrincipal()
            ?: return call.respond(HttpStatusCode.Unauthorized, ErrorResponse("mtls_required"))
    val subject = principal.subjectDn
    if (!observerAllowList.isObserver(subject)) {
        auditLog.write(
            AuditEvent(
                occurredAt = Clock.System.now(),
                eventType = AuditEventType.OBSERVER_FORBIDDEN,
                actorSubject = subject,
                success = false,
                detailJson = """{"endpoint":"$endpoint"}""",
            ),
        )
        return call.respond(HttpStatusCode.Forbidden, ErrorResponse("observer_required"))
    }
    if (rateLimiter != null && !rateLimiter.tryConsume(subject)) {
        auditLog.write(
            AuditEvent(
                occurredAt = Clock.System.now(),
                eventType = AuditEventType.OBSERVABILITY_RATE_LIMIT_EXCEEDED,
                actorSubject = subject,
                success = false,
                detailJson = """{"endpoint":"$endpoint"}""",
            ),
        )
        return call.respond(HttpStatusCode.TooManyRequests, ErrorResponse("rate_limited"))
    }
    try {
        block(subject)
    } catch (ex: IllegalArgumentException) {
        call.respond(HttpStatusCode.UnprocessableEntity, ErrorResponse("malformed_request", ex.message))
    } catch (ex: Exception) {
        auditLog.write(
            AuditEvent(
                occurredAt = Clock.System.now(),
                eventType = AuditEventType.OBSERVABILITY_ERROR,
                actorSubject = subject,
                success = false,
                detailJson = """{"endpoint":"$endpoint","exception":"${ex.javaClass.simpleName}"}""",
            ),
        )
        call.respond(HttpStatusCode.InternalServerError, ErrorResponse("internal_error"))
    }
}

private fun ApplicationCall.intParam(name: String): Int? = request.queryParameters[name]?.toIntOrNull()

private fun ApplicationCall.instantParam(name: String): Instant? =
    request.queryParameters[name]?.takeIf { it.isNotBlank() }?.let { Instant.parse(it) }

private fun KekObservation.toDto(): KekObservationDto =
    KekObservationDto(
        id = id,
        fingerprint = fingerprint,
        status = status,
        createdAt = createdAt.toString(),
        activatedAt = activatedAt?.toString(),
        quiescedAt = quiescedAt?.toString(),
        retiredAt = retiredAt?.toString(),
    )

private fun DekObservation.toDto(): DekObservationDto =
    DekObservationDto(
        handleHex = handleHex,
        kekId = kekId,
        createdAt = createdAt.toString(),
        updatedAt = updatedAt.toString(),
    )

private fun JwtSigningKeyObservation.toDto(): JwtSigningKeyObservationDto =
    JwtSigningKeyObservationDto(
        kidHex = kidHex,
        status = status,
        algorithm = algorithm,
        curve = curve,
        wrappedUnderKekId = wrappedUnderKekId,
        createdAt = createdAt.toString(),
        activatedAt = activatedAt?.toString(),
        quiescedAt = quiescedAt?.toString(),
        retiredAt = retiredAt?.toString(),
        retainUntil = retainUntil?.toString(),
    )

private fun AuditObservation.toDto(): AuditObservationDto =
    AuditObservationDto(
        id = id,
        occurredAt = occurredAt.toString(),
        eventType = eventType,
        actorSubject = actorSubject,
        kekId = kekId,
        dekHandleHex = dekHandleHex,
        success = success,
        detailJson = detailJson,
    )

private fun RotationObservation.toDto(): RotationObservationDto =
    RotationObservationDto(
        id = id,
        occurredAt = occurredAt.toString(),
        eventType = eventType,
        actorSubject = actorSubject,
        kekId = kekId,
        detailJson = detailJson,
    )
