CREATE TABLE secrets (
  name TEXT PRIMARY KEY,
  value BLOB NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  auth_method TEXT NOT NULL CHECK (auth_method IN ("pass-opaque", "webauthn")),
  display_name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE opaque_user_data (
  client_id TEXT NOT NULL PRIMARY KEY,
  credential_id TEXT NOT NULL UNIQUE,
  registration_record TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)

