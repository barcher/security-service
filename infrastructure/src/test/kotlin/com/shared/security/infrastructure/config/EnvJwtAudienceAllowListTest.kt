package com.shared.security.infrastructure.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class EnvJwtAudienceAllowListTest {
    @Test
    fun `null or blank value denies every audience`() {
        val empty = EnvJwtAudienceAllowList(null)
        val blank = EnvJwtAudienceAllowList("   ")
        val hash = hashSubject("CN=anything")

        assertFalse(empty.isAllowed("CN=anything", "any-audience"))
        assertFalse(blank.isAllowed("CN=anything", "any-audience"))
        // Sanity: the hash function returns a 16-char hex string.
        assertEquals(16, hash.length)
        assertTrue(hash.matches(Regex("^[0-9a-f]+$")))
    }

    @Test
    fun `known subject + known audience returns true`() {
        val dn = "CN=workautomations-monolith,O=WorkAutomations"
        val hash = hashSubject(dn)
        val raw = "$hash=workautomations-api"
        val allow = EnvJwtAudienceAllowList(raw)

        assertTrue(allow.isAllowed(dn, "workautomations-api"))
        assertFalse(allow.isAllowed(dn, "other-api"))
    }

    @Test
    fun `multiple audiences per subject are parsed`() {
        val dn = "CN=monolith,O=WA"
        val hash = hashSubject(dn)
        val raw = "$hash=api,$hash=internal,$hash=admin"
        val allow = EnvJwtAudienceAllowList(raw)

        assertTrue(allow.isAllowed(dn, "api"))
        assertTrue(allow.isAllowed(dn, "internal"))
        assertTrue(allow.isAllowed(dn, "admin"))
        assertFalse(allow.isAllowed(dn, "other"))
    }

    @Test
    fun `cross-subject audience leakage is impossible`() {
        val monolith = "CN=monolith,O=WA"
        val financial = "CN=financial,O=WA"
        val raw =
            buildString {
                append(hashSubject(monolith)).append("=monolith-api,")
                append(hashSubject(financial)).append("=financial-api")
            }
        val allow = EnvJwtAudienceAllowList(raw)

        assertTrue(allow.isAllowed(monolith, "monolith-api"))
        assertFalse(allow.isAllowed(monolith, "financial-api"))
        assertTrue(allow.isAllowed(financial, "financial-api"))
        assertFalse(allow.isAllowed(financial, "monolith-api"))
    }

    @Test
    fun `malformed entry without equals raises IllegalArgumentException`() {
        assertThrows(IllegalArgumentException::class.java) {
            EnvJwtAudienceAllowList("not-a-valid-entry")
        }
    }

    @Test
    fun `malformed entry with non-hex hash raises IllegalArgumentException`() {
        assertThrows(IllegalArgumentException::class.java) {
            EnvJwtAudienceAllowList("ZZZZZZZZZZZZZZZZ=workautomations-api")
        }
    }

    @Test
    fun `subject DN comparison is case-insensitive and whitespace-trimmed`() {
        val dn = "CN=workautomations-monolith,O=WorkAutomations"
        val hash = hashSubject(dn)
        val allow = EnvJwtAudienceAllowList("$hash=api")

        assertTrue(allow.isAllowed(dn, "api"))
        assertTrue(allow.isAllowed(dn.uppercase(), "api"))
        assertTrue(allow.isAllowed("  $dn  ", "api"))
    }
}
