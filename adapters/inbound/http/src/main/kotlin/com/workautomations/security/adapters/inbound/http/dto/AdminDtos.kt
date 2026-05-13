package com.workautomations.security.adapters.inbound.http.dto

import kotlinx.serialization.Serializable

@Serializable
data class RotateKekResponse(
    val newPublicKeyB64: String,
    val newPrivateKeyB64: String,
    val note: String = "Stream B returns key material only; activation lands in Stream C",
)

@Serializable
data class KeyStatusResponse(
    val isAvailable: Boolean,
    val activeKekFingerprint: String? = null,
)
