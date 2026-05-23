-- V5: jwt_signing_keys — JWT signing-key lifecycle table for the security service.
--
-- Stream K (proposal §8). One row per ES256 (P-256) signing keypair. State machine:
-- STAGED → ACTIVE → PRIOR → QUIESCED → RETIRED, mirroring the V1 `keks` table.
--
-- Storage rules (proposal §3.5):
--   - `wrapped_private_key_bytes` holds the KEK-wrapped envelope of the ES256 private
--     key (PKCS#8 DER). The wrap goes through KekEnvelopePort (proposal §3.4b) — never
--     CryptoKeyServicePort directly from the JWT layer. Plaintext private bytes never
--     touch this row.
--   - `public_key_spki` holds the X.509 SubjectPublicKeyInfo (DER) of the public key.
--     This is intentionally public — it is the input to the /v1/jwks document.
--
-- Singleton-ACTIVE invariant enforced by a generated column + unique index (same idiom
-- as the V1 `keks` table). This guarantees at most one ACTIVE row at any moment; the
-- atomic STAGED→ACTIVE transition is performed in a single DB transaction that
-- demotes the previous ACTIVE → PRIOR before promoting the new STAGED → ACTIVE.
--
-- Audit cross-reference: every transition emits an audit row in `audit_events` with the
-- `kid` (this table's PK) recorded in `detail_json`. See JWT_OPERATIONS.md for the full
-- catalog of event types.

CREATE TABLE jwt_signing_keys (
    kid                         VARBINARY(16)   NOT NULL,
    status                      ENUM('STAGED', 'ACTIVE', 'PRIOR', 'QUIESCED', 'RETIRED') NOT NULL,
    algorithm                   VARCHAR(8)      NOT NULL DEFAULT 'ES256',
    curve                       VARCHAR(16)     NOT NULL DEFAULT 'P-256',
    wrapped_private_key_bytes   MEDIUMBLOB      NOT NULL,
    public_key_spki             BLOB            NOT NULL,
    -- Reference to the KEK that wrapped the private key. KEK rotation triggers a JWT
    -- key rewrap as a separate operator step (HSM ceremony §4); this column lets the
    -- rewrap job know which keys are still under PRIOR KEKs.
    wrapped_under_kek_id        CHAR(36)        NOT NULL,
    created_at                  DATETIME(6)     NOT NULL,
    activated_at                DATETIME(6)     NULL,
    quiesced_at                 DATETIME(6)     NULL,
    retired_at                  DATETIME(6)     NULL,
    -- Retention floor — after RETIRED, the row may not be deleted until this timestamp.
    -- JwtSigningKeyRetentionJob (SKS-K17) enforces this on a daily sweep.
    retain_until                DATETIME(6)     NULL,
    PRIMARY KEY (kid),
    KEY ix_jwt_signing_keys_status (status, created_at),
    KEY ix_jwt_signing_keys_wrapped_under_kek (wrapped_under_kek_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Partial uniqueness via the same "generated column + unique index" idiom as the V1
-- `keks` table: at most one row may be ACTIVE at any moment. A SECOND row attempting
-- to insert with status=ACTIVE (or UPDATE to ACTIVE) raises a duplicate-key error,
-- which the ActivateJwtSigningKeyUseCase catches and surfaces as a clear conflict.
ALTER TABLE jwt_signing_keys
    ADD COLUMN active_singleton_marker TINYINT GENERATED ALWAYS AS (
        CASE WHEN status = 'ACTIVE' THEN 1 ELSE NULL END
    ) STORED,
    ADD UNIQUE KEY uk_jwt_signing_keys_active_singleton (active_singleton_marker);
