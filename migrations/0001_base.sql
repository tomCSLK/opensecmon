-- Base schema of opensecmon: metadata, users, sessions, audit log, mail settings and sent notifications.

CREATE TABLE meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT;

INSERT INTO meta (key, value) VALUES ('created_at', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

-- Local users; every user is an administrator. `language` (`de`, `en`) NULL follows the browser.
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    language      TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

-- `id` is the SHA-256 hex digest of the cookie token, so a leaked database does not reveal usable session
-- cookies. Times are Unix seconds (UTC); `last_seen_at` is the last activity (sign-out after a time without it).
CREATE TABLE sessions (
    id           TEXT PRIMARY KEY NOT NULL,
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token   TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
) STRICT;

CREATE INDEX sessions_user_id ON sessions (user_id);
CREATE INDEX sessions_expires_at ON sessions (expires_at);

-- Who changed what and when: changes, sign-ins (also failed ones) and sign-outs. `detail` is a message
-- (`Msg::encode`, never a secret). `user_name` and `object_name` are copies as of the time, so entries stay
-- readable after renames and deletions. Kept for `retention_audit_days`.
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY,
    ts_ms       INTEGER NOT NULL,
    user_name   TEXT NOT NULL,
    address     TEXT,
    action      TEXT NOT NULL,
    kind        TEXT NOT NULL,
    object_id   INTEGER,
    object_name TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX audit_log_ts ON audit_log (ts_ms);

-- E-mail settings (a single row). The thresholds of the instant mail and the time of the daily report follow
-- with the notifications (phase 7).
CREATE TABLE mail_settings (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    enabled      INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    host         TEXT NOT NULL DEFAULT '',
    port         INTEGER NOT NULL DEFAULT 587 CHECK (port BETWEEN 1 AND 65535),
    security     TEXT NOT NULL DEFAULT 'starttls' CHECK (security IN ('none', 'starttls', 'tls')),
    username     TEXT,
    password_enc BLOB,
    from_address TEXT NOT NULL DEFAULT '',
    recipients   TEXT NOT NULL DEFAULT '',
    language     TEXT NOT NULL DEFAULT 'de',
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- A password only makes sense together with a user name.
    CHECK (password_enc IS NULL OR username IS NOT NULL)
) STRICT;

INSERT INTO mail_settings (id) VALUES (1);

-- Sent mails: instant mails for new matches, daily reports and test mails.
CREATE TABLE notifications (
    id         INTEGER PRIMARY KEY,
    ts_ms      INTEGER NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('match', 'report', 'test')),
    subject    TEXT NOT NULL,
    recipients TEXT NOT NULL,
    ok         INTEGER NOT NULL CHECK (ok IN (0, 1)),
    error      TEXT
) STRICT;

CREATE INDEX notifications_ts ON notifications (ts_ms);
