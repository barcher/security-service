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
         * Load the allow-list from `SECURITY_DASHBOARD_OBSERVER_SUBJECTS`. Same parsing
         * convention as [StaticAdminAllowList.fromEnv]: split on `;` first (because each
         * RFC2253 DN contains commas), fall back to `,` only when no `;` is present.
         */
        fun fromEnv(): StaticDashboardObserverAllowList {
            val raw = System.getenv("SECURITY_DASHBOARD_OBSERVER_SUBJECTS") ?: ""
            val sep = if (raw.contains(';')) ";" else ","
            val entries =
                raw.split(sep)
                    .map { it.trim() }
                    .filter { it.isNotBlank() }
                    .toSet()
            return StaticDashboardObserverAllowList(entries)
        }
    }
}
