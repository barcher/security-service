package com.shared.security.tools.decryptcli

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HardCapEnforcerTest {
    @Test
    fun `accepts a small row count without opt-in`() {
        val outcome = HardCapEnforcer.check(rowCount = 1000L, spanHours = 1L, iUnderstandLargeExport = false)
        assertEquals(HardCapEnforcer.Outcome.Allowed, outcome)
    }

    @Test
    fun `rejects row count above 10 000 without opt-in`() {
        val outcome = HardCapEnforcer.check(rowCount = 10_001L, spanHours = null, iUnderstandLargeExport = false)
        assertTrue(outcome is HardCapEnforcer.Outcome.CapExceeded)
        assertTrue((outcome as HardCapEnforcer.Outcome.CapExceeded).reason.contains("row count"))
    }

    @Test
    fun `accepts row count above 10 000 with opt-in`() {
        val outcome = HardCapEnforcer.check(rowCount = 50_000L, spanHours = null, iUnderstandLargeExport = true)
        assertEquals(HardCapEnforcer.Outcome.Allowed, outcome)
    }

    @Test
    fun `rejects time span over 24 h without opt-in`() {
        val outcome = HardCapEnforcer.check(rowCount = 1L, spanHours = 48L, iUnderstandLargeExport = false)
        assertTrue(outcome is HardCapEnforcer.Outcome.CapExceeded)
        assertTrue((outcome as HardCapEnforcer.Outcome.CapExceeded).reason.contains("time span"))
    }

    @Test
    fun `accepts time span over 24 h with opt-in`() {
        val outcome = HardCapEnforcer.check(rowCount = 1L, spanHours = 720L, iUnderstandLargeExport = true)
        assertEquals(HardCapEnforcer.Outcome.Allowed, outcome)
    }
}
