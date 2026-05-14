-- V3: audit_events — HMAC-SHA-512 hash-chained audit log.
--
-- Schema matches proposal §10. Every row's row_hmac is HMAC-SHA-512 of (canonical payload
-- || prev_hmac), keyed by AUDIT_HMAC_KEY. The chain reads:
--
--     row_hmac[n] = HMAC-SHA-512(AUDIT_HMAC_KEY, payload[n] || prev_hmac[n])
--     prev_hmac[n] = row_hmac[n - 1]    (zero-byte sentinel for n = 1)
--
-- Tampering with any prior row's payload or row_hmac invalidates every subsequent
-- row_hmac. Chain verification is run by AuditLogShipperJob before each cold-storage ship
-- and is exposed as a maintenance route in Stream E.
--
-- The id is monotonic; the row_hmac chain follows id order. No deletes; AuditRetentionJob
-- removes rows older than 7 years AFTER cold-storage ship is confirmed, in monotonic id
-- batches so the chain remains contiguous over the surviving range.

CREATE TABLE audit_events (
    id              BIGINT          NOT NULL AUTO_INCREMENT,
    occurred_at     DATETIME(6)     NOT NULL,
    event_type      VARCHAR(40)     NOT NULL,
    actor_subject   VARCHAR(255)    NULL,
    dek_handle      VARBINARY(16)   NULL,
    kek_id          CHAR(36)        NULL,
    success         TINYINT(1)      NOT NULL,
    detail_json     JSON            NULL,
    prev_hmac       VARBINARY(64)   NOT NULL,
    row_hmac        VARBINARY(64)   NOT NULL,
    PRIMARY KEY (id),
    KEY ix_audit_occurred_at (occurred_at),
    KEY ix_audit_event_type (event_type, occurred_at),
    KEY ix_audit_actor_subject (actor_subject, occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
