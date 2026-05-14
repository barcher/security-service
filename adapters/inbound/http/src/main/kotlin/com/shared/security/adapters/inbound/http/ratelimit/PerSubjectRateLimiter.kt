package com.shared.security.adapters.inbound.http.ratelimit

import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.min

/**
 * Per-subject token bucket. Each subject DN gets its own bucket with [capacity] tokens that
 * refill at [refillTokensPerSecond]. `tryConsume(subjectDn)` returns true if a token was
 * available (and consumed) and false otherwise.
 *
 * The bucket is **strictly local-process** — Stream B's deployment posture is single-instance
 * per service; horizontal scale-out lands in Stream C (SKS-C06..C09) along with the persistent
 * audit chain and a distributed limiter. Bucket state is held in a [ConcurrentHashMap] keyed
 * by subject DN so concurrent calls from the same client don't race.
 *
 * The [clock] dependency makes the limiter trivially testable — advancing test clocks gives
 * deterministic refill behaviour without thread sleeps.
 */
class PerSubjectRateLimiter(
    private val capacity: Double,
    private val refillTokensPerSecond: Double,
    private val clock: Clock = Clock.System,
) {
    init {
        require(capacity > 0) { "capacity must be positive, was $capacity" }
        require(refillTokensPerSecond > 0) { "refillTokensPerSecond must be positive, was $refillTokensPerSecond" }
    }

    private data class Bucket(var tokens: Double, var lastRefill: Instant)

    private val buckets = ConcurrentHashMap<String, Bucket>()

    /**
     * Try to consume one token for [subjectDn]. Returns true iff a token was available.
     *
     * Refill is lazy: the bucket only updates on a call. Long-idle subjects refill all the
     * way to [capacity] on their next call rather than running a background timer.
     */
    fun tryConsume(subjectDn: String): Boolean {
        val now = clock.now()
        val bucket =
            buckets.compute(subjectDn) { _, existing ->
                if (existing == null) {
                    Bucket(tokens = capacity, lastRefill = now)
                } else {
                    val elapsedSeconds = (now - existing.lastRefill).inWholeMilliseconds.toDouble() / MILLIS_PER_SECOND
                    val refilled = existing.tokens + elapsedSeconds * refillTokensPerSecond
                    existing.tokens = min(refilled, capacity)
                    existing.lastRefill = now
                    existing
                }
            }!!
        return if (bucket.tokens >= 1.0) {
            bucket.tokens -= 1.0
            true
        } else {
            false
        }
    }

    /** Test-only inspection of remaining tokens (lazy-refilled to [now]). */
    fun tokensFor(subjectDn: String): Double = buckets[subjectDn]?.tokens ?: capacity

    companion object {
        private const val MILLIS_PER_SECOND = 1000.0

        /** Default unwrap-call limit suitable for dev: 5 tokens, 1 per second. */
        fun defaultUnwrapLimiter(clock: Clock = Clock.System): PerSubjectRateLimiter =
            PerSubjectRateLimiter(capacity = 5.0, refillTokensPerSecond = 1.0, clock = clock)
    }
}
