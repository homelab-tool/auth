CREATE TABLE secrets (
  name TEXT PRIMARY KEY,
  value BLOB NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  display_name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE opaque_user_data (
  client_id TEXT NOT NULL PRIMARY KEY,
  credential_id TEXT NOT NULL UNIQUE,
  registration_record TEXT NOT NULL,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  ksf_algorithm TEXT NOT NULL,
  ksf_salt BLOB NOT NULL,
  ksf_params TEXT NOT NULL,
  ksf_output_len INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE webauthn_credentials (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id    BLOB NOT NULL UNIQUE,
  public_key       BLOB NOT NULL,
  attestation_type TEXT NOT NULL,
  transport        TEXT NOT NULL,
  aaguid           BLOB,
  sign_count       INTEGER NOT NULL,
  clone_warning    INTEGER NOT NULL,
  backup_eligible  INTEGER NOT NULL,
  backup_state     INTEGER NOT NULL,
  purpose          TEXT NOT NULL,
  name             TEXT NOT NULL,
  created_at       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at     TEXT
);

CREATE TABLE totp_secrets (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  secret     TEXT NOT NULL,
  enabled    INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id)
);

CREATE TABLE site_configs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  hostname   TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)
