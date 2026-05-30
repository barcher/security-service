package com.shared.security.domain.oauth

/**
 * Identifier for a refresh-token *family* — the chain of rotated refresh tokens descending
 * from a single original issuance (RFC 9700 §4.14, proposal §4.6).
 *
 * Refresh-token rotation-on-use means each refresh swaps the presented token for a new one
 * in the same family. Reuse-detection works at family granularity: presenting an
 * already-rotated token revokes the *entire* family. This VO names that family so the
 * later refresh-token store + reuse-detection logic can group rotations.
 *
 * **Scope note:** this is a forward-defined value object only. The `oauth_refresh_tokens`
 * table, issuance, rotation and reuse-detection logic are deliberately NOT part of the
 * provider skeleton — they land with the (gated) reversal of CLAUDE.md invariant #5. Defining
 * the VO now lets the domain vocabulary be complete without pulling any refresh-token
 * *behavior* forward.
 */
@JvmInline
value class RefreshTokenFamily(val value: String) {
    init {
        require(value.isNotBlank()) { "refresh-token family id must not be blank" }
    }
}
