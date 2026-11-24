CREATE TABLE users (
    id              CHAR(36)        NOT NULL,
    google_id       VARCHAR(255)    NULL,
    github_id       VARCHAR(255)    NULL,
    email           VARCHAR(320)    NOT NULL DEFAULT '',
    full_name       VARCHAR(255)    NOT NULL DEFAULT '',
    profile_picture VARCHAR(2048)   NULL,
    last_provider   VARCHAR(32)     NOT NULL DEFAULT 'google',
    created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_google_id (google_id),
    UNIQUE KEY uq_users_github_id (github_id),
    KEY idx_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE refresh_tokens (
    id         CHAR(36)        NOT NULL,
    user_id    CHAR(36)        NOT NULL,
    token_hash CHAR(64)        NOT NULL,
    family_id  CHAR(36)        NOT NULL,
    expires_at TIMESTAMP       NOT NULL,
    revoked_at TIMESTAMP       NULL,
    created_at TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_refresh_token_hash (token_hash),
    KEY idx_refresh_tokens_user (user_id),
    KEY idx_refresh_tokens_family (family_id),
    KEY idx_refresh_tokens_expires (expires_at),
    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
