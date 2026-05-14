-- V2: deks — Wrapped DEK store.
--
-- One row per logical DEK handle the security service has issued. The wrapped_dek_bytes
-- column holds the current wrap (under the kek_id referenced); wrapped_dek_bytes_pending
-- is populated during KEK rotation (proposal §8.3): the DekRotationJob writes the new wrap
-- under the next ACTIVE KEK into _pending, then atomically promotes it to wrapped_dek_bytes
-- in a single transaction once verified.
--
-- The handle is the only identifier shown to callers. It is opaque and not derivable from
-- key material; readers find a DEK via its handle, never via the KEK identity.

CREATE TABLE deks (
    handle                     VARBINARY(16)  NOT NULL,
    kek_id                     CHAR(36)       NOT NULL,
    wrapped_dek_bytes          MEDIUMBLOB     NOT NULL,
    wrapped_dek_bytes_pending  MEDIUMBLOB     NULL,
    created_at                 DATETIME(6)    NOT NULL,
    updated_at                 DATETIME(6)    NOT NULL,
    PRIMARY KEY (handle),
    KEY ix_deks_kek_id (kek_id, created_at),
    CONSTRAINT fk_deks_kek_id FOREIGN KEY (kek_id) REFERENCES keks (id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
