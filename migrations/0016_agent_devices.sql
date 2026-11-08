-- Computers that report their installed software themselves (the agent API, docs/agent-api.md).
--
-- `name` is the host of their assets (unique together with the names of `ssh_hosts`, checked by the app).
-- `token_hash`: SHA-256 (hex) of the computer's token, empty before the enrollment and after revoking; the token
-- itself is never stored. `code_hash`: SHA-256 of the one-time code (written without dash), `code_secret` the same
-- code encrypted with secret.key so the page can show it until `code_expires_ms`; all three are cleared when the
-- code is used. `revoked`: the token was revoked; the assets stay until the computer is deleted.
-- The fields of the last report (`os_name` … `last_report_ms`) are written by the reports (step 3).
CREATE TABLE agent_devices (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    token_hash      TEXT NOT NULL DEFAULT '',
    code_hash       TEXT NOT NULL DEFAULT '',
    code_secret     BLOB,
    code_expires_ms INTEGER,
    revoked         INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    hostname        TEXT NOT NULL DEFAULT '',
    agent_name      TEXT NOT NULL DEFAULT '',
    agent_version   TEXT NOT NULL DEFAULT '',
    os_name         TEXT NOT NULL DEFAULT '',
    distro          TEXT NOT NULL DEFAULT '',
    release         TEXT NOT NULL DEFAULT '',
    packages        INTEGER NOT NULL DEFAULT 0,
    report_hash     TEXT NOT NULL DEFAULT '',
    enrolled_ms     INTEGER,
    last_seen_ms    INTEGER,
    last_report_ms  INTEGER,
    last_error      TEXT NOT NULL DEFAULT '',
    created_ms      INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX agent_devices_token ON agent_devices (token_hash) WHERE token_hash != '';
CREATE UNIQUE INDEX agent_devices_code ON agent_devices (code_hash) WHERE code_hash != '';
