package com.shared.security.application.ports

/**
 * Stream L L.0 — decides whether a given mTLS subject DN is permitted to invoke the
 * read-only observability endpoints under `/v1/observability/`. Structurally separate
 * from [AdminAllowList]: a compromised observer cert can read lifecycle metadata but
 * cannot rotate, unwrap, or sign. That separation is enforced by:
 *
 *   1. Distinct env vars (`SECURITY_DASHBOARD_OBSERVER_SUBJECTS` vs
 *      `SECURITY_ADMIN_SUBJECTS`).
 *   2. Distinct route prefixes (`/v1/observability/<op>` vs `/v1/admin/<op>`).
 *   3. ArchUnit S-14 (this port is referenced only by `ObservabilityRoutes.kt`).
 *
 * The audit chain records the mTLS subject DN on every observation request so the two
 * lanes are distinguishable in forensics after the fact.
 */
fun interface DashboardObserverAllowList {
    fun isObserver(subjectDn: String): Boolean
}

class StaticDashboardObserverAllowList(
    private val allowedSubjects: Set<String>,
) : DashboardObserverAllowList {
    override fun isObserver(subjectDn: String): Boolean = subjectDn in allowedSubjects

    companion object {
        /**
         * Load the allow-list from `SECURITY_DASHBOARD_OBSERVER_SUBJECTS`. Splits on `;`
         * only. The previous variant fell back to `,` when no `;` was present, which was
         * an operator-trap: a single RFC 2253 DN contains commas internally, so the
         * fallback would shred it into fragments and the allow-list would silently reject
         * every caller. With `;`-only the single-DN case works without any separator and
         * the multi-DN case is unambiguous. Matches [StaticAdminAllowList.fromEnv].
         */
        fun fromEnv(): StaticDashboardObserverAllowList {
            val raw = System.getenv("SECURITY_DASHBOARD_OBSERVER_SUBJECTS") ?: ""
            val entries =
                raw.split(";")
                    .map { it.trim() }
                    .filter { it.isNotBlank() }
                    .toSet()
            return StaticDashboardObserverAllowList(entries)
        }
    }
}
