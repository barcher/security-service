package com.shared.security.application.ports

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class StaticDashboardObserverAllowListTest {
    @Test
    fun `empty set denies every subject`() {
        val list = StaticDashboardObserverAllowList(emptySet())
        assertFalse(list.isObserver("CN=anyone,O=WorkAutomations"))
    }

    @Test
    fun `matches exact subject DN string`() {
        val dn = "CN=workautomations-dashboard-observer,O=WorkAutomations"
        val list = StaticDashboardObserverAllowList(setOf(dn))
        assertTrue(list.isObserver(dn))
        assertFalse(list.isObserver("CN=workautomations-monolith,O=WorkAutomations"))
    }

    @Test
    fun `case-sensitive match — DN whitespace matters`() {
        // The RFC2253 DN is case-sensitive at the attribute-value level for our purposes;
        // we don't normalize. A misspelled cert (different case) should NOT match.
        val list = StaticDashboardObserverAllowList(setOf("CN=Observer-1,O=WorkAutomations"))
        assertFalse(list.isObserver("CN=observer-1,O=WorkAutomations"))
    }

    @Test
    fun `observer allow-list is disjoint from admin allow-list — load both independently`() {
        // Structural separation: even if the same set were passed to both, they'd answer
        // separately. This test pins the invariant that one list never falls back to the
        // other. (Real wiring sources from two different env vars.)
        val observerOnly =
            StaticDashboardObserverAllowList(setOf("CN=workautomations-dashboard-observer,O=WorkAutomations"))
        val adminOnly = StaticAdminAllowList(setOf("CN=workautomations-admin,O=WorkAutomations"))
        assertFalse(observerOnly.isObserver("CN=workautomations-admin,O=WorkAutomations"))
        assertFalse(adminOnly.isAdmin("CN=workautomations-dashboard-observer,O=WorkAutomations"))
    }
}
