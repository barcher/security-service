-- V4: legacy DEK provenance.
--
-- The Stream-E `import-monolith-deks` CLI imports each row from the monolith's
-- principal_encryption_keys table into security-service `deks`, rewrapping under the
-- active KEK in the process. The new `legacy_key_id` column records the source row's id
-- so:
--   - the CLI is idempotent (re-runs skip rows already imported via UNIQUE index)
--   - the LegacyEnvelopeRewriteJob in the monolith can resolve old `enc:v2:<key_id>:`
--     envelopes to the new dek_handle via this provenance link
--   - audit / forensic queries can trace any current DEK back to its pre-Phase-14 origin

ALTER TABLE deks
    ADD COLUMN legacy_key_id VARCHAR(36) NULL,
    ADD UNIQUE KEY uk_deks_legacy_key_id (legacy_key_id);
