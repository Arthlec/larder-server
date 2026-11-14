CREATE TABLE households (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    invite_code TEXT NOT NULL UNIQUE
);

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    household_id  TEXT REFERENCES households(id)
);

-- One row per synced entity: always its latest version (or a tombstone).
-- `seq` is a server-wide change number; devices pull "everything after seq N".
CREATE TABLE records (
    household_id TEXT NOT NULL REFERENCES households(id),
    kind         TEXT NOT NULL,
    id           TEXT NOT NULL,
    updated_at   INTEGER NOT NULL,
    deleted      INTEGER NOT NULL,
    payload      TEXT NOT NULL,
    seq          INTEGER NOT NULL UNIQUE,
    PRIMARY KEY (household_id, kind, id)
);
CREATE INDEX records_household_seq ON records(household_id, seq);

-- Signed-in devices. Only the SHA-256 of each token is stored.
CREATE TABLE sessions (
    token_hash   TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id),
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);

-- Server-local values such as the TLS certificate and key.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
