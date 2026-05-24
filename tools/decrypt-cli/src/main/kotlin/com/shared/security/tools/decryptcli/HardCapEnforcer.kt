package com.shared.security.tools.decryptcli

/**
 * Phase 14 Stream M (SKS-M13) — operator-facing hard cap.
 *
 * The CLI refuses to decrypt large row sets without the operator explicitly
 * opting in via `--i-understand-large-export`. Caps:
 *
 *   * **Row count:** [MAX_ROW_COUNT] rows.
 *   * **Time span:** [MAX_SPAN_HOURS] hours between `--since` and `--until`.
 *
 * The cap is enforced AFTER argument parsing but BEFORE the audit row is
 * written — a CLI invocation that is rejected at this gate never produces an
 * OPERATOR_DECRYPT_RUN audit row. This matches the existing pattern: the
 * audit row is the record that an operator *actually started* the decrypt,
 * not the record that they attempted to start it.
 *
 * The opt-in value is recorded in the audit row's `detail_json.i_understand_large_export`
 * field per CLAUDE.md rule 26.
 */
object HardCapEnforcer {
    const val MAX_ROW_COUNT: Long = 10_000L
    const val MAX_SPAN_HOURS: Long = 24L

    sealed class Outcome {
        data object Allowed : Outcome()

        data class CapExceeded(val reason: String) : Outcome()
    }

    fun check(
        rowCount: Long,
        spanHours: Long?,
        iUnderstandLargeExport: Boolean,
    ): Outcome {
        if (iUnderstandLargeExport) {
            return Outcome.Allowed
        }
        if (rowCount > MAX_ROW_COUNT) {
            return Outcome.CapExceeded(
                "row count $rowCount exceeds the $MAX_ROW_COUNT-row hard cap; " +
                    "pass --i-understand-large-export to override",
            )
        }
        if (spanHours != null && spanHours > MAX_SPAN_HOURS) {
            return Outcome.CapExceeded(
                "time span ${spanHours}h exceeds the ${MAX_SPAN_HOURS}h hard cap; " +
                    "pass --i-understand-large-export to override",
            )
        }
        return Outcome.Allowed
    }
}
