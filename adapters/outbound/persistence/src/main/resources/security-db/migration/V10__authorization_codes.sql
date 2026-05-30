-- V10: authorization_codes — single-use OAuth 2.0 authorization codes (RFC 6749 §4.1 + PKCE
-- RFC 7636), issued at /authorize and redeemed once at /token.
--
-- Stored HASHED, never plaintext. An authorization code is a short-lived bearer credential
-- the provider verifies by re-hashing the presented value, exactly like a refresh token: it
-- is a one-way hash with NOTHING to decrypt, so there is no KEK/DEK envelope and no
-- *_dek_handle sibling (the same exemption today's sessions.refresh_token_hash relies on —
-- the EncryptedColumnSchemaLinter sibling rule applies only to *encrypted* columns).
--
--   - `code_hash` is the one-way hash (SHA-256) of the high-entropy code value and is the
--     primary key — codes are looked up by hash at redemption.
--   - `code_challenge` + `code_challenge_method` carry the PKCE binding. Only S256 is
--     supported (no `plain`); the column is constrained to that single value.
--   - `redirect_uri` is the exact URI the code is bound to (RFC 6749 §4.1.3 — redemption
--     must present the identical value).
--   - `redeemed_at` enforces single use: it is NULL until the code is consumed; a second
--     redemption attempt finds a non-NULL value and is rejected (and, per RFC 6749 §4.1.2,
--     is grounds to revoke tokens already issued for the code).
--   - `scopes` is the space-delimited set consented at /authorize.
--
-- The provider skeleton lands the table so the schema exists; the /authorize issue path and
-- the /token authorization-code redeem path that write/consume these rows arrive later. An
-- expired-code sweeper (scheduler job) is likewise a later-phase addition; `expires_at` is
-- indexed so that sweep is cheap.

CREATE TABLE authorization_codes (
    code_hash             VARBINARY(32) NOT NULL,
    client_id             VARCHAR(255)  NOT NULL,
    subject               VARCHAR(255)  NOT NULL,
    redirect_uri          VARCHAR(2048) NOT NULL,
    code_challenge        VARCHAR(128)  NOT NULL,
    code_challenge_method ENUM('S256')  NOT NULL,
    scopes                VARCHAR(1024) NOT NULL,
    issued_at             DATETIME(6)   NOT NULL,
    expires_at            DATETIME(6)   NOT NULL,
    redeemed_at           DATETIME(6)   NULL,
    PRIMARY KEY (code_hash),
    KEY ix_authorization_codes_expires_at (expires_at),
    CONSTRAINT fk_authorization_codes_client
        FOREIGN KEY (client_id) REFERENCES oauth_clients (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
