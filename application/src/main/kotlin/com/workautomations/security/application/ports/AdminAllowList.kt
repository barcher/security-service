package com.workautomations.security.application.ports

/**
 * Decides whether a given mTLS subject DN is permitted to invoke admin endpoints under
 * the `/v1/admin/` path.
 *
 * The allow-list is intentionally a small primitive (set of subject DNs) so it can be sourced
 * from env vars, k8s ConfigMap, or a secret store interchangeably. No business logic should
 * be smuggled in via this contract; it is a pure predicate.
 */
fun interface AdminAllowList {
    fun isAdmin(subjectDn: String): Boolean
}

class StaticAdminAllowList(private val allowedSubjects: Set<String>) : AdminAllowList {
    override fun isAdmin(subjectDn: String): Boolean = subjectDn in allowedSubjects

    companion object {
        /**
         * Load the allow-list from the `SECURITY_ADMIN_SUBJECTS` env var. Comma-separated
         * list of full RFC2253 subject DNs (e.g.
         * `SECURITY_ADMIN_SUBJECTS=CN=admin-1,O=WorkAutomations,CN=admin-2,O=WorkAutomations`).
         *
         * **Be careful:** the RFC2253 form includes commas inside each DN. Use semicolons to
         * separate entries when DNs contain commas — this parser splits on `;` first, then
         * falls back to `,` for backwards compatibility when no `;` is present.
         */
        fun fromEnv(): StaticAdminAllowList {
            val raw = System.getenv("SECURITY_ADMIN_SUBJECTS") ?: ""
            val sep = if (raw.contains(';')) ";" else ","
            val entries =
                raw.split(sep)
                    .map { it.trim() }
                    .filter { it.isNotBlank() }
                    .toSet()
            return StaticAdminAllowList(entries)
        }
    }
}
