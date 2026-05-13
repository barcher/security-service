package com.workautomations.security.infrastructure.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RateLimitConfigTest {
    private fun envOf(map: Map<String, String?>): (String) -> String? = { map[it] }

    @Test
    fun `fromEnv returns defaults when no env vars set`() {
        val config = RateLimitConfig.fromEnv(envOf(emptyMap()))

        assertTrue(config.enabled)
        assertEquals(5.0, config.capacity)
        assertEquals(1.0, config.refillTokensPerSecond)
    }

    @Test
    fun `fromEnv parses explicit numeric values`() {
        val config =
            RateLimitConfig.fromEnv(
                envOf(
                    mapOf(
                        RateLimitConfig.ENV_CAPACITY to "20",
                        RateLimitConfig.ENV_REFILL to "2.5",
                    ),
                ),
            )

        assertEquals(20.0, config.capacity)
        assertEquals(2.5, config.refillTokensPerSecond)
        assertTrue(config.enabled)
    }

    @Test
    fun `fromEnv treats blank values as defaults`() {
        val config =
            RateLimitConfig.fromEnv(
                envOf(
                    mapOf(
                        RateLimitConfig.ENV_CAPACITY to "  ",
                        RateLimitConfig.ENV_REFILL to "",
                    ),
                ),
            )

        assertEquals(5.0, config.capacity)
        assertEquals(1.0, config.refillTokensPerSecond)
    }

    @Test
    fun `fromEnv disables limiter when ENABLED=false`() {
        val config =
            RateLimitConfig.fromEnv(envOf(mapOf(RateLimitConfig.ENV_ENABLED to "false")))

        assertEquals(false, config.enabled)
    }

    @Test
    fun `fromEnv accepts common truthy and falsy string forms for ENABLED`() {
        val truthy = listOf("true", "TRUE", "1", "yes", "on", "On  ")
        val falsy = listOf("false", "FALSE", "0", "no", "off")

        truthy.forEach { v ->
            assertTrue(
                RateLimitConfig.fromEnv(envOf(mapOf(RateLimitConfig.ENV_ENABLED to v))).enabled,
                "value '$v' should parse as enabled=true",
            )
        }
        falsy.forEach { v ->
            assertEquals(
                false,
                RateLimitConfig.fromEnv(envOf(mapOf(RateLimitConfig.ENV_ENABLED to v))).enabled,
                "value '$v' should parse as enabled=false",
            )
        }
    }

    @Test
    fun `fromEnv ignores invalid capacity and refill when ENABLED=false`() {
        // Disabled mode short-circuits validation — the limiter is never consulted, so the
        // sentinel values produced are not exercised.
        val config =
            RateLimitConfig.fromEnv(
                envOf(
                    mapOf(
                        RateLimitConfig.ENV_ENABLED to "false",
                        RateLimitConfig.ENV_CAPACITY to "garbage",
                        RateLimitConfig.ENV_REFILL to "-1",
                    ),
                ),
            )

        assertEquals(false, config.enabled)
    }

    @Test
    fun `fromEnv rejects non-numeric capacity when enabled`() {
        assertThrows(RateLimitConfigException::class.java) {
            RateLimitConfig.fromEnv(envOf(mapOf(RateLimitConfig.ENV_CAPACITY to "abc")))
        }
    }

    @Test
    fun `fromEnv rejects non-numeric refill when enabled`() {
        assertThrows(RateLimitConfigException::class.java) {
            RateLimitConfig.fromEnv(envOf(mapOf(RateLimitConfig.ENV_REFILL to "xyz")))
        }
    }

    @Test
    fun `fromEnv rejects zero or negative capacity when enabled`() {
        assertThrows(RateLimitConfigException::class.java) {
            RateLimitConfig.fromEnv(envOf(mapOf(RateLimitConfig.ENV_CAPACITY to "0")))
        }
        assertThrows(RateLimitConfigException::class.java) {
            RateLimitConfig.fromEnv(envOf(mapOf(RateLimitConfig.ENV_CAPACITY to "-3")))
        }
    }

    @Test
    fun `fromEnv rejects zero or negative refill when enabled`() {
        assertThrows(RateLimitConfigException::class.java) {
            RateLimitConfig.fromEnv(envOf(mapOf(RateLimitConfig.ENV_REFILL to "0")))
        }
        assertThrows(RateLimitConfigException::class.java) {
            RateLimitConfig.fromEnv(envOf(mapOf(RateLimitConfig.ENV_REFILL to "-0.5")))
        }
    }

    @Test
    fun `fromEnv rejects unrecognised ENABLED string`() {
        assertThrows(RateLimitConfigException::class.java) {
            RateLimitConfig.fromEnv(envOf(mapOf(RateLimitConfig.ENV_ENABLED to "maybe")))
        }
    }

    @Test
    fun `constructor rejects zero capacity when enabled`() {
        assertThrows(IllegalArgumentException::class.java) {
            RateLimitConfig(enabled = true, capacity = 0.0, refillTokensPerSecond = 1.0)
        }
    }

    @Test
    fun `constructor rejects zero refill when enabled`() {
        assertThrows(IllegalArgumentException::class.java) {
            RateLimitConfig(enabled = true, capacity = 1.0, refillTokensPerSecond = 0.0)
        }
    }

    @Test
    fun `constructor allows any values when disabled`() {
        // Should not throw — the sentinel construction path used by SecurityServiceModule
        // when the limiter is disabled relies on this.
        RateLimitConfig(enabled = false, capacity = 1.0, refillTokensPerSecond = 1.0)
    }
}
