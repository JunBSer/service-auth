CREATE TABLE IF NOT EXISTS sessions
(
    session_id    UUID PRIMARY KEY,
    user_id       UUID      NOT NULL,
    refresh_token TEXT      NOT NULL,
    created_at    TIMESTAMP DEFAULT NOW(),
    expires_at    TIMESTAMP NOT NULL,

    FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE
);

