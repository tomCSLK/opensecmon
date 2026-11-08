-- opennetmon with its self-signed certificate: the SHA-256 fingerprint the user entered (`AB:CD:…`, empty = the
-- certificate must come from a known authority). With a fingerprint only that certificate is accepted.
ALTER TABLE inventory_settings ADD COLUMN onm_cert_sha256 TEXT NOT NULL DEFAULT '';
