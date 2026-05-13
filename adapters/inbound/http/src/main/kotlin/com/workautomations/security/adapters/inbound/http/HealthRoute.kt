package com.workautomations.security.adapters.inbound.http

import io.ktor.http.HttpStatusCode
import io.ktor.server.response.respond
import io.ktor.server.routing.Routing
import io.ktor.server.routing.get

/**
 * GET /v1/health — liveness probe for the security service.
 *
 * Stream A returns 200 unconditionally over plaintext. After Stream B (SKS-B01) the
 * route is reachable only over mTLS; the readiness check that ensures the KEK is
 * loaded and the active KEK can wrap+unwrap a probe DEK lands in SKS-C06 as part of
 * `KekRotationHealthJob`.
 */
fun Routing.installHealthRoute() {
    get("/v1/health") {
        call.respond(HttpStatusCode.OK, HealthResponse(status = "ok", service = "security-service"))
    }
}
