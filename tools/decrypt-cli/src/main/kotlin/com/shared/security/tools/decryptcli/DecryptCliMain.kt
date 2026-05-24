package com.shared.security.tools.decryptcli

/**
 * Phase 14 Stream M (SKS-M05 / SKS-M11) — operator decrypt CLI entry point.
 *
 * **Scope (single-sided per `feedback_operator_decrypt_cli_single_sided.md`):** the
 * security-service CLI is the ONLY operator decrypt CLI in either repo. It targets
 * security-service-owned ciphertext:
 *
 *   * `security_keys.deks.wrapped_dek_bytes` — unwrap to raw bytes for incident
 *     response.
 *   * `security_keys.jwt_signing_keys.wrapped_private_key_bytes` (post-Stream-K) —
 *     unwrap to PKCS#8 PEM for token-forensics replay.
 *   * Future encrypted security-service state.
 *
 * **NEVER bundled into the running `security-app` docker image** (CLAUDE.md "Shared
 * Key Service" rule 24). Runs on an operator workstation or jump-host. Distribution:
 *
 *   ./gradlew :tools:decrypt-cli:installDist
 *
 * **NEVER reachable via HTTP** (CLAUDE.md rule 24, ArchUnit S-15). The `main()` here
 * is not registered with any `routing { }` block.
 *
 * **Every invocation emits exactly one `OPERATOR_DECRYPT_RUN` audit row** to the
 * security-service audit chain BEFORE any unwrap (CLAUDE.md rule 26). Audit row
 * contains operator email, reason, argument vector, row count, output destination,
 * and the two opt-in flags. Plaintext never appears in the audit row.
 *
 * M.0 ships this as a help-only stub. M.1 (SKS-M11) replaces the stub body with
 * the full argument parser + executors + audit emission + crypto-op dispatch.
 */
fun main(args: Array<String>) {
    if (args.isEmpty() || args[0] == "--help" || args[0] == "-h") {
        System.out.println(HELP_TEXT)
        kotlin.system.exitProcess(0)
    }
    // M.0 placeholder — full implementation lands in SKS-M11.
    System.err.println(
        "decrypt-cli (Stream M M.0 stub): argument parsing + audit emission " +
            "+ executor dispatch land in M.1 (SKS-M10/M11). See the inventory at " +
            "meta-project/work-items/phases/phase14/stream_m_inventory.md.",
    )
    kotlin.system.exitProcess(2)
}

private val HELP_TEXT =
    """
    decrypt-cli — operator decrypt CLI (Phase 14 Stream M)

    Status: M.0 stub. Full argument surface lands in M.1.

    Scope (single-sided per feedback_operator_decrypt_cli_single_sided.md):
      security-service-owned ciphertext only. The monolith does NOT host a
      sibling CLI.

    Planned argument surface (see proposal §4.1):
      --since <iso8601>            time-window scope start
      --until <iso8601>            time-window scope end
      --table <name> [...]         scope tables
      --ids <pk,pk,...>            explicit primary keys
      --key-handle <hex>           decrypt all rows bound to one DEK
      --audit-event-id <id>        decrypt one audit event's detail_json
      --output {json|jsonl|csv}    default json
      --output-file <path>         requires --i-accept-plaintext-on-disk
      --dry-run                    show what would be decrypted, no plaintext
      --operator-email <addr>      REQUIRED — RFC 5322 email
      --reason <string>            REQUIRED — 16–256 chars
      --correlation-id <uuid>      optional
      --i-understand-large-export  overrides the 10 000-row / 24 h hard cap
      --i-accept-plaintext-on-disk required if --output-file is set

    Audit (CLAUDE.md rule 26): each invocation emits exactly one
      OPERATOR_DECRYPT_RUN row to security_keys.audit_events BEFORE any
      unwrap. Plaintext is never logged or persisted by default.

    Runbook (lands in M.2): docs/OPERATOR_DECRYPT_RUNBOOK.md.
    """.trimIndent()
