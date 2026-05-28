-- V7: email_lookup_hmac_key — the symmetric HMAC key behind the monolith's email
-- blind-index lookup. The monolith stores an opaque 16-byte blind index alongside each
-- encrypted email; equality lookups (findByEmail) match on the blind index instead of
-- the plaintext. The HMAC key NEVER leaves the security service: the monolith POSTs a
-- normalized email to /v1/blind-index/email and receives only the 16-byte hash.
--
-- Storage rules (mirrors the V5 jwt_signing_keys posture):
--   - `wrapped_key_bytes` holds the KEK-wrapped envelope of the 32-byte HMAC-SHA-256 key.
--     The wrap goes through KekEnvelopePort with AAD "email-lookup-hmac-key:<version>" so
--     a wrapped HMAC blob can never be substituted for a DEK or JWT-key envelope under the
--     same KEK. Plaintext key bytes never touch this row.
--   - `wrapped_under_kek_id` lets a KEK-rotation rewrap job find keys still under PRIOR KEKs.
--
-- The key is generated on first use (no operator ceremony, like DEK provisioning). It is
-- expected NEVER to rotate in normal operation: rotation invalidates every stored blind
-- index and requires re-hashing every row. `version` + the RETIRED status exist to support
-- a future dual-hash rotation window, not routine rotation.
--
-- Singleton-ACTIVE invariant via the generated-column + unique-index idiom (same as V1 keks
-- and V5 jwt_signing_keys): at most one ACTIVE row at any moment. A concurrent second insert
-- races to the unique constraint and loses; the loser re-reads the winner's key.

CREATE TABLE email_lookup_hmac_key (
    id                       CHAR(36)        NOT NULL,
    version                  INT             NOT NULL DEFAULT 1,
    status                   ENUM('ACTIVE', 'RETIRED') NOT NULL,
    wrapped_key_bytes        MEDIUMBLOB      NOT NULL,
    wrapped_under_kek_id     CHAR(36)        NOT NULL,
    created_at               DATETIME(6)     NOT NULL,
    retired_at               DATETIME(6)     NULL,
    PRIMARY KEY (id),
    KEY ix_email_lookup_hmac_key_status (status, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

ALTER TABLE email_lookup_hmac_key
    ADD COLUMN active_singleton_marker TINYINT GENERATED ALWAYS AS (
        CASE WHEN status = 'ACTIVE' THEN 1 ELSE NULL END
    ) STORED,
    ADD UNIQUE KEY uk_email_lookup_hmac_key_active_singleton (active_singleton_marker);
