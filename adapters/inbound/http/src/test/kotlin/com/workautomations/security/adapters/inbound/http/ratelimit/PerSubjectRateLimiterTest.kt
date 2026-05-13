package com.workautomations.security.adapters.inbound.http.ratelimit

import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PerSubjectRateLimiterTest {
    private class TestClock(var now: Instant = Instant.fromEpochMilliseconds(0)) : Clock {
        override fun now(): Instant = now
    }

    @Test
    fun `bucket starts at capacity and tryConsume returns true until depleted`() {
        val clock = TestClock()
        val limiter = PerSubjectRateLimiter(capacity = 3.0, refillTokensPerSecond = 1.0, clock = clock)

        assertTrue(limiter.tryConsume("cn=a"))
        assertTrue(limiter.tryConsume("cn=a"))
        assertTrue(limiter.tryConsume("cn=a"))
        assertFalse(limiter.tryConsume("cn=a"))
    }

    @Test
    fun `bucket refills at configured rate`() {
        val clock = TestClock()
        val limiter = PerSubjectRateLimiter(capacity = 2.0, refillTokensPerSecond = 2.0, clock = clock)

        assertTrue(limiter.tryConsume("cn=a"))
        assertTrue(limiter.tryConsume("cn=a"))
        assertFalse(limiter.tryConsume("cn=a"))

        // Advance 500 ms → 1 token refilled at 2 tokens/sec.
        clock.now = Instant.fromEpochMilliseconds(500)
        assertTrue(limiter.tryConsume("cn=a"))
        assertFalse(limiter.tryConsume("cn=a"))
    }

    @Test
    fun `bucket does not refill above capacity`() {
        val clock = TestClock()
        val limiter = PerSubjectRateLimiter(capacity = 2.0, refillTokensPerSecond = 1.0, clock = clock)

        assertTrue(limiter.tryConsume("cn=a"))
        // Idle for 10 seconds → would refill 10 tokens; capped at 2.
        clock.now = Instant.fromEpochMilliseconds(10_000)
        assertTrue(limiter.tryConsume("cn=a"))
        assertTrue(limiter.tryConsume("cn=a"))
        assertFalse(limiter.tryConsume("cn=a"))
    }

    @Test
    fun `each subject has an independent bucket`() {
        val clock = TestClock()
        val limiter = PerSubjectRateLimiter(capacity = 1.0, refillTokensPerSecond = 1.0, clock = clock)

        assertTrue(limiter.tryConsume("cn=alice"))
        assertFalse(limiter.tryConsume("cn=alice"))
        // Bob has a fresh full bucket.
        assertTrue(limiter.tryConsume("cn=bob"))
        assertFalse(limiter.tryConsume("cn=bob"))
    }

    @Test
    fun `default unwrap limiter has 5 capacity and 1 token per second refill`() {
        val clock = TestClock()
        val limiter = PerSubjectRateLimiter.defaultUnwrapLimiter(clock = clock)

        // First 5 consumes succeed (capacity = 5).
        repeat(5) { assertTrue(limiter.tryConsume("cn=x"), "consume ${it + 1} should succeed") }
        assertFalse(limiter.tryConsume("cn=x"))

        // 1 second later → 1 token refilled.
        clock.now = Instant.fromEpochMilliseconds(1000)
        assertTrue(limiter.tryConsume("cn=x"))
        assertFalse(limiter.tryConsume("cn=x"))
    }

    @Test
    fun `capacity and refill rate must be positive`() {
        val errs =
            listOf(
                runCatching { PerSubjectRateLimiter(capacity = 0.0, refillTokensPerSecond = 1.0) },
                runCatching { PerSubjectRateLimiter(capacity = -1.0, refillTokensPerSecond = 1.0) },
                runCatching { PerSubjectRateLimiter(capacity = 1.0, refillTokensPerSecond = 0.0) },
                runCatching { PerSubjectRateLimiter(capacity = 1.0, refillTokensPerSecond = -1.0) },
            )
        assertEquals(4, errs.count { it.isFailure })
    }
}
