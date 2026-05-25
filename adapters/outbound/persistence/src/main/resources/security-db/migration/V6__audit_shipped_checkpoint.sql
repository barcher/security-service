-- Stream C follow-up SHIP-02 (2026-05-24) — single-row checkpoint for AuditLogShipperJob.
--
-- The shipper job moves audit_events rows to cold storage in batches and needs to know
-- which row id was last successfully shipped (so the next run resumes from there).
-- We use a single-row table (id = 1) rather than scanning audit_events.row_hmac because
-- the read pattern is "max id where shipped=true" which would require an extra column on
-- the hot audit table; a separate one-row table keeps audit_events untouched.
--
-- The AuditRetentionJob also reads this value — it MUST NOT delete a row whose id is
-- greater than the last shipped id, otherwise the audit history is gone before it reaches
-- the cold-storage shipper.

CREATE TABLE audit_shipped_checkpoint (
  id           TINYINT NOT NULL PRIMARY KEY DEFAULT 1,
  last_shipped_id BIGINT NOT NULL DEFAULT 0,
  updated_at   TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  CONSTRAINT audit_shipped_checkpoint_singleton CHECK (id = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO audit_shipped_checkpoint (id, last_shipped_id) VALUES (1, 0);
