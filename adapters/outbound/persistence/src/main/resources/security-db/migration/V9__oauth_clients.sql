-- V9: oauth_clients — the statically-provisioned OAuth 2.0 / OIDC client registry.
--
-- The provider has NO dynamic client registration (RFC 7591). The set of first-party
-- clients is fixed config, seeded on startup by SeedOAuthClientsUseCase (insert-if-absent,
-- idempotent) and mutated thereafter only by an admin-lane CLI in a later phase. This table
-- is the persisted backing of that registry; it is a superset *view* over the existing
-- SECURITY_JWT_AUDIENCE_ALLOWLIST env var (the env list stays the authoritative Gate-2
-- source — this table never bypasses it).
--
-- Client authentication is mTLS (tls_client_auth, RFC 8705) for confidential clients and
-- PKCE-with-no-secret (none) for the public browser client. There is deliberately NO stored
-- client secret column: the provider never persists a recoverable client credential, so
-- there is nothing here to KEK/DEK-wrap and no *_dek_handle sibling is required (no encrypted
-- column on this table).
--
--   - `subject_dn` is the operational-lane certificate subject DN bound 1:1 to a
--     tls_client_auth client (the Gate-1 identity at /token). NULL for public clients. The
--     unique index makes the DN→client binding 1:1 and composes with — never collapses —
--     the four-lane subject-DN audit model.
--   - `allowed_grant_types`, `allowed_scopes`, `allowed_audiences` are space-delimited token
--     lists (the OAuth `scope`-style wire form). Application code parses them into the
--     domain VOs; storing the wire form keeps the registry human-auditable in the DB.
--   - `enabled` lets an operator disable a client (rejected at /token) without deleting the
--     row and losing its audit history.

CREATE TABLE oauth_clients (
    client_id            VARCHAR(255)  NOT NULL,
    auth_method          ENUM('tls_client_auth', 'none') NOT NULL,
    subject_dn           VARCHAR(512)  NULL,
    allowed_grant_types  VARCHAR(512)  NOT NULL,
    allowed_scopes       VARCHAR(1024) NOT NULL,
    allowed_audiences    VARCHAR(1024) NOT NULL,
    enabled              BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at           DATETIME(6)   NOT NULL,
    updated_at           DATETIME(6)   NOT NULL,
    PRIMARY KEY (client_id),
    UNIQUE KEY uk_oauth_clients_subject_dn (subject_dn)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
