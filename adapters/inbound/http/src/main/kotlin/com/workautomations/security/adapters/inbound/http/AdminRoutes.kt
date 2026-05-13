package com.workautomations.security.adapters.inbound.http

import com.workautomations.security.adapters.inbound.http.auth.clientPrincipal
import com.workautomations.security.adapters.inbound.http.dto.ErrorResponse
import com.workautomations.security.adapters.inbound.http.dto.KeyStatusResponse
import com.workautomations.security.adapters.inbound.http.dto.RotateKekResponse
import com.workautomations.security.application.ports.AdminAllowList
import com.workautomations.security.application.ports.AuditEvent
import com.workautomations.security.application.ports.AuditEventType
import com.workautomations.security.application.ports.AuditLogPort
import com.workautomations.security.application.usecases.GenerateNewKekPairUseCase
import com.workautomations.security.application.usecases.GetKeyStatusUseCase
import io.ktor.http.HttpStatusCode
import io.ktor.server.response.respond
import io.ktor.server.routing.Routing
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import kotlinx.datetime.Clock

/**
 * Admin routes — every endpoint requires the caller's mTLS subject DN to be present in
 * [AdminAllowList]. Non-admin authenticated callers receive HTTP 403 plus an
 * `ADMIN_FORBIDDEN` audit event (the call was authenticated but not authorized).
 *
 * Note: `MtlsAuthPlugin` runs ahead of these routes and guarantees a non-null
 * `clientPrincipal()`. If `clientPrincipal()` is null here, something is structurally wrong
 * with the wiring and we fail closed with 401.
 */
fun Routing.installAdminRoutes(
    adminAllowList: AdminAllowList,
    auditLog: AuditLogPort,
    generateNewKekPair: GenerateNewKekPairUseCase,
    getKeyStatus: GetKeyStatusUseCase,
) {
    route("/v1/admin") {
        post("/rotate-kek") {
            val principal =
                call.clientPrincipal()
                    ?: return@post call.respond(HttpStatusCode.Unauthorized, ErrorResponse("mtls_required"))
            if (!adminAllowList.isAdmin(principal.subjectDn)) {
                auditLog.write(
                    AuditEvent(
                        occurredAt = Clock.System.now(),
                        eventType = AuditEventType.ADMIN_FORBIDDEN,
                        actorSubject = principal.subjectDn,
                        success = false,
                        detailJson = """{"endpoint":"/v1/admin/rotate-kek"}""",
                    ),
                )
                return@post call.respond(HttpStatusCode.Forbidden, ErrorResponse("admin_required"))
            }
            val pair = generateNewKekPair.execute(actorSubject = principal.subjectDn)
            call.respond(
                HttpStatusCode.OK,
                RotateKekResponse(newPublicKeyB64 = pair.publicKeyB64, newPrivateKeyB64 = pair.privateKeyB64),
            )
        }

        get("/key-status") {
            val principal =
                call.clientPrincipal()
                    ?: return@get call.respond(HttpStatusCode.Unauthorized, ErrorResponse("mtls_required"))
            if (!adminAllowList.isAdmin(principal.subjectDn)) {
                auditLog.write(
                    AuditEvent(
                        occurredAt = Clock.System.now(),
                        eventType = AuditEventType.ADMIN_FORBIDDEN,
                        actorSubject = principal.subjectDn,
                        success = false,
                        detailJson = """{"endpoint":"/v1/admin/key-status"}""",
                    ),
                )
                return@get call.respond(HttpStatusCode.Forbidden, ErrorResponse("admin_required"))
            }
            val summary = getKeyStatus.execute(actorSubject = principal.subjectDn)
            call.respond(
                HttpStatusCode.OK,
                KeyStatusResponse(
                    isAvailable = summary.isAvailable,
                    activeKekFingerprint = summary.activeKekFingerprint,
                ),
            )
        }
    }
}
