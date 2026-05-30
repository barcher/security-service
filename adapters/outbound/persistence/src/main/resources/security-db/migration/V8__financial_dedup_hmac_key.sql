-- V8: financial_dedup_hmac_key — the symmetric HMAC key behind financial-service's
-- transaction dedup blind index. financial-service stores an opaque blind index in
-- `financial_transactions.dedup_hash`; import resolution matches on that index instead of
-- a brute-forceable bare SHA-256 over the natural-key tuple. The natural-key preimage folds
-- in the (encrypted-at-rest) merchant token plus institution reference fields, so a bare
-- SHA-256 would be a guessable fingerprint of encrypted data — keying it with a secret HMAC
-- key the caller never holds closes that gap.
--
-- The HMAC key NEVER leaves the security service: financial-service computes a local
-- SHA-256 PREHASH of the natural-key preimage and POSTs only that 32-byte digest to
-- /v1/blind-index/financial-dedup; the service returns HMAC-SHA-256(key, prehash). The raw
-- merchant token never crosses the wire (this is the deliberate difference from the email
-- blind index, whose plaintext is non-sensitive enough to send directly).
--
-- This is a SEPARATE key from V7's email_lookup_hmac_key: separate purpose, separate
-- namespace. One purpose's key can never compute another purpose's indices (the AAD pins
-- "financial-dedup-hmac-key:<version>", distinct from "email-lookup-hmac-key:<version>").
--
-- Storage rules (mirrors V5 jwt_signing_keys + V7 email_lookup_hmac_key posture):
--   - `wrapped_key_bytes` holds the KEK-wrapped envelope of the 32-byte HMAC-SHA-256 key.
--     The wrap goes through KekEnvelopePort with AAD "financial-dedup-hmac-key:<version>" so
--     a wrapped HMAC blob can never be substituted for a DEK, JWT-key, or email-key envelope
--     under the same KEK. Plaintext key bytes never touch this row.
--   - `wrapped_under_kek_id` lets a KEK-rotation rewrap job find keys still under PRIOR KEKs.
--
-- The key is generated on first use (no operator ceremony, like DEK provisioning). It is
-- expected NEVER to rotate in normal operation: rotation invalidates every stored dedup
-- blind index and requires an app-layer recompute of every financial_transactions row.
-- `version` + the RETIRED status exist to support a future dual-hash rotation window, not
-- routine rotation.
--
-- Singleton-ACTIVE invariant via the generated-column + unique-index idiom (same as V1 keks,
-- V5 jwt_signing_keys, V7 email_lookup_hmac_key): at most one ACTIVE row at any moment. A
-- concurrent second insert races to the unique constraint and loses; the loser re-reads the
-- winner's key.

CREATE TABLE financial_dedup_hmac_key (
    id                       CHAR(36)        NOT NULL,
    version                  INT             NOT NULL DEFAULT 1,
    status                   ENUM('ACTIVE', 'RETIRED') NOT NULL,
    wrapped_key_bytes        MEDIUMBLOB      NOT NULL,
    wrapped_under_kek_id     CHAR(36)        NOT NULL,
    created_at               DATETIME(6)     NOT NULL,
    retired_at               DATETIME(6)     NULL,
    PRIMARY KEY (id),
    KEY ix_financial_dedup_hmac_key_status (status, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

ALTER TABLE financial_dedup_hmac_key
    ADD COLUMN active_singleton_marker TINYINT GENERATED ALWAYS AS (
        CASE WHEN status = 'ACTIVE' THEN 1 ELSE NULL END
    ) STORED,
    ADD UNIQUE KEY uk_financial_dedup_hmac_key_active_singleton (active_singleton_marker);
