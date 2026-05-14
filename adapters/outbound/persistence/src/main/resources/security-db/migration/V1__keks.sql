-- V1: keks — KEK lifecycle table for the security service.
--
-- One row per ML-KEM-768 keypair the service has known about. Status enum drives the
-- STAGED → ACTIVE → PRIOR → RETIRED state machine from proposal §8. At any time there is
-- at most one ACTIVE row; PRIOR rows are accepted on unwrap during the quiesce window and
-- transition to RETIRED via KekPriorTtlJob once all DEKs referencing them are rewrapped.
--
-- Fingerprint is the SHA-256 of the public key in colon-hex form (95 chars). Stored
-- separately from any key material — public keys are not stored here; the active
-- public/private bytes come from FileMountKekProvider at startup and are held in memory
-- only. Storing the fingerprint lets the audit log reference the KEK without holding the
-- bytes.

CREATE TABLE keks (
    id                  CHAR(36)        NOT NULL,
    fingerprint         VARCHAR(95)     NOT NULL,
    status              ENUM('STAGED', 'ACTIVE', 'PRIOR', 'RETIRED') NOT NULL,
    created_at          DATETIME(6)     NOT NULL,
    activated_at        DATETIME(6)     NULL,
    quiesced_at         DATETIME(6)     NULL,
    retired_at          DATETIME(6)     NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_keks_fingerprint (fingerprint),
    KEY ix_keks_status (status, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Partial uniqueness via MySQL's "functional index on conditional expression" idiom: at most
-- one row may be ACTIVE at any time. Enforced via a generated column with a unique index.
ALTER TABLE keks
    ADD COLUMN active_singleton_marker TINYINT GENERATED ALWAYS AS (
        CASE WHEN status = 'ACTIVE' THEN 1 ELSE NULL END
    ) STORED,
    ADD UNIQUE KEY uk_keks_one_active (active_singleton_marker);
