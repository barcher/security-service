package com.shared.security.adapters.outbound.persistence

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SecurityDatabaseConfigTest {
    private fun envOf(map: Map<String, String?>): (String) -> String? = { map[it] }

    @Test
    fun `isEnabled defaults to false`() {
        assertFalse(SecurityDatabaseConfig.isEnabled(envOf(emptyMap())))
    }

    @Test
    fun `isEnabled accepts common truthy strings`() {
        listOf("true", "TRUE", "1", "yes", "on").forEach {
            assertTrue(
                SecurityDatabaseConfig.isEnabled(envOf(mapOf(SecurityDatabaseConfig.ENV_ENABLED to it))),
                "value '$it' should parse as true",
            )
        }
    }

    @Test
    fun `isEnabled accepts common falsy strings`() {
        listOf("false", "FALSE", "0", "no", "off").forEach {
            assertFalse(
                SecurityDatabaseConfig.isEnabled(envOf(mapOf(SecurityDatabaseConfig.ENV_ENABLED to it))),
                "value '$it' should parse as false",
            )
        }
    }

    @Test
    fun `isEnabled throws on unrecognised string`() {
        assertThrows(SecurityDatabaseConfigException::class.java) {
            SecurityDatabaseConfig.isEnabled(envOf(mapOf(SecurityDatabaseConfig.ENV_ENABLED to "maybe")))
        }
    }

    @Test
    fun `fromEnv applies defaults for URL user and pool size`() {
        val config =
            SecurityDatabaseConfig.fromEnv(
                envOf(mapOf(SecurityDatabaseConfig.ENV_PASSWORD to "secret")),
            )

        assertEquals(SecurityDatabaseConfig.DEFAULT_URL, config.jdbcUrl)
        assertEquals(SecurityDatabaseConfig.DEFAULT_USER, config.user)
        assertEquals(SecurityDatabaseConfig.DEFAULT_POOL_SIZE, config.poolSize)
        assertEquals("secret", config.password)
    }

    @Test
    fun `fromEnv requires password`() {
        assertThrows(SecurityDatabaseConfigException::class.java) {
            SecurityDatabaseConfig.fromEnv(envOf(emptyMap()))
        }
    }

    @Test
    fun `fromEnv parses overrides`() {
        val config =
            SecurityDatabaseConfig.fromEnv(
                envOf(
                    mapOf(
                        SecurityDatabaseConfig.ENV_URL to "jdbc:mysql://other:3306/db",
                        SecurityDatabaseConfig.ENV_USER to "alice",
                        SecurityDatabaseConfig.ENV_PASSWORD to "p",
                        SecurityDatabaseConfig.ENV_POOL_SIZE to "20",
                    ),
                ),
            )

        assertEquals("jdbc:mysql://other:3306/db", config.jdbcUrl)
        assertEquals("alice", config.user)
        assertEquals(20, config.poolSize)
    }

    @Test
    fun `fromEnv rejects non-integer pool size`() {
        assertThrows(SecurityDatabaseConfigException::class.java) {
            SecurityDatabaseConfig.fromEnv(
                envOf(
                    mapOf(
                        SecurityDatabaseConfig.ENV_PASSWORD to "p",
                        SecurityDatabaseConfig.ENV_POOL_SIZE to "abc",
                    ),
                ),
            )
        }
    }

    @Test
    fun `fromEnv rejects out-of-range pool size`() {
        assertThrows(SecurityDatabaseConfigException::class.java) {
            SecurityDatabaseConfig.fromEnv(
                envOf(
                    mapOf(
                        SecurityDatabaseConfig.ENV_PASSWORD to "p",
                        SecurityDatabaseConfig.ENV_POOL_SIZE to "0",
                    ),
                ),
            )
        }
        assertThrows(SecurityDatabaseConfigException::class.java) {
            SecurityDatabaseConfig.fromEnv(
                envOf(
                    mapOf(
                        SecurityDatabaseConfig.ENV_PASSWORD to "p",
                        SecurityDatabaseConfig.ENV_POOL_SIZE to "9999",
                    ),
                ),
            )
        }
    }
}
