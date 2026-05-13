package com.workautomations.security.adapters.inbound.http

import kotlinx.serialization.Serializable

@Serializable
data class HealthResponse(val status: String, val service: String)
