package com.shared.security.infrastructure.logging

import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.filter.Filter
import ch.qos.logback.core.spi.FilterReply

/**
 * Suppresses HikariCP log noise produced when an Apple Silicon dev machine wakes from sleep.
 *
 * During sleep the JVM is paused, so HikariCP's keepalive task can't fire. On wake, the
 * HouseKeeper observes a multi-minute clock delta and warns about it, every existing
 * connection is found to be dead and is marked as broken with a full stack trace, and
 * validation fails on whatever the pool tries next. None of this is actionable in dev.
 *
 * Gated by `LOG_SUPPRESS_HIKARI_SLEEP_NOISE` (env var or `-D` system property). Default off
 * so production retains every WARN — clock-leap warnings in prod indicate real issues
 * (GC stall, VM pause, NTP jump) and must not be silenced.
 */
class HikariSleepNoiseFilter : Filter<ILoggingEvent>() {
    override fun decide(event: ILoggingEvent): FilterReply {
        val name = event.loggerName ?: return FilterReply.NEUTRAL
        if (!name.startsWith("com.zaxxer.hikari")) return FilterReply.NEUTRAL
        if (!readFlag()) return FilterReply.NEUTRAL
        val msg = event.formattedMessage ?: return FilterReply.NEUTRAL
        return if (SLEEP_NOISE_FRAGMENTS.any { it in msg }) FilterReply.DENY else FilterReply.NEUTRAL
    }

    companion object {
        private const val FLAG = "LOG_SUPPRESS_HIKARI_SLEEP_NOISE"

        private val SLEEP_NOISE_FRAGMENTS =
            listOf(
                "clock leap detected",
                "marked as broken",
                "Failed to validate connection",
                "Keepalive failed",
                "Possibly consider using a shorter maxLifetime",
            )

        // Read lazily on each matching event so the flag picks up values injected by the
        // dotenv loader at the top of main() — file-level logger field initialization
        // would otherwise force logback (and this filter) to be constructed first.
        private fun readFlag(): Boolean =
            System.getenv(FLAG)?.toBoolean() == true ||
                System.getProperty(FLAG)?.toBoolean() == true
    }
}
