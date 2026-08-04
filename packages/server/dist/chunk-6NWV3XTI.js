// src/schema.ts
var LOCALWEBAUTHN_SCHEMA_VERSION = 1;
var LOCALWEBAUTHN_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS localwebauthn_migrations (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS localwebauthn_enrollment_grants (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash BLOB NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  token_consumed_at INTEGER,
  session_hash BLOB,
  session_expires_at INTEGER,
  completed_at INTEGER,
  revoked_at INTEGER,
  approved_by_user_id TEXT,
  created_at INTEGER NOT NULL,
  CHECK (length(token_hash) = 32),
  CHECK (expires_at > created_at),
  CHECK (
    (session_hash IS NULL AND session_expires_at IS NULL)
    OR (session_hash IS NOT NULL AND session_expires_at IS NOT NULL)
  )
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS localwebauthn_active_grant_user_idx
  ON localwebauthn_enrollment_grants(user_id)
  WHERE completed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS localwebauthn_grant_expiry_idx
  ON localwebauthn_enrollment_grants(expires_at, completed_at, revoked_at);

CREATE TABLE IF NOT EXISTS localwebauthn_challenges (
  id_hash BLOB PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('registration', 'authentication')),
  challenge TEXT NOT NULL,
  user_id TEXT,
  grant_id TEXT REFERENCES localwebauthn_enrollment_grants(id),
  authorization_session_hash BLOB,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  created_at INTEGER NOT NULL,
  CHECK (length(id_hash) = 32),
  CHECK (
    kind = 'authentication'
    OR user_id IS NOT NULL
  ),
  CHECK (
    (grant_id IS NULL OR authorization_session_hash IS NULL)
    AND (kind = 'registration' OR (grant_id IS NULL AND authorization_session_hash IS NULL))
  )
) STRICT;

CREATE INDEX IF NOT EXISTS localwebauthn_challenge_expiry_idx
  ON localwebauthn_challenges(expires_at, consumed_at);

CREATE TABLE IF NOT EXISTS localwebauthn_credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0 CHECK (counter >= 0),
  transports_json TEXT NOT NULL DEFAULT '[]',
  device_type TEXT NOT NULL CHECK (device_type IN ('singleDevice', 'multiDevice')),
  backed_up INTEGER NOT NULL DEFAULT 0 CHECK (backed_up IN (0, 1)),
  label TEXT NOT NULL DEFAULT 'Passkey',
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS localwebauthn_credential_user_idx
  ON localwebauthn_credentials(user_id, revoked_at);

CREATE TABLE IF NOT EXISTS localwebauthn_sessions (
  id_hash BLOB PRIMARY KEY,
  user_id TEXT NOT NULL,
  credential_id TEXT NOT NULL REFERENCES localwebauthn_credentials(id),
  authenticated_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  revoked_at INTEGER,
  CHECK (length(id_hash) = 32),
  CHECK (expires_at > authenticated_at)
) STRICT;

CREATE INDEX IF NOT EXISTS localwebauthn_session_user_idx
  ON localwebauthn_sessions(user_id, revoked_at, expires_at);

CREATE TABLE IF NOT EXISTS localwebauthn_transaction_guard (
  value INTEGER NOT NULL CHECK (value = 1)
) STRICT;
`;
var LOCALWEBAUTHN_POSTGRES_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS localwebauthn_migrations (
  version INTEGER PRIMARY KEY,
  applied_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS localwebauthn_enrollment_grants (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash BYTEA NOT NULL UNIQUE,
  expires_at BIGINT NOT NULL,
  token_consumed_at BIGINT,
  session_hash BYTEA,
  session_expires_at BIGINT,
  completed_at BIGINT,
  revoked_at BIGINT,
  approved_by_user_id TEXT,
  created_at BIGINT NOT NULL,
  CHECK (octet_length(token_hash) = 32),
  CHECK (expires_at > created_at),
  CHECK (
    (session_hash IS NULL AND session_expires_at IS NULL)
    OR (session_hash IS NOT NULL AND session_expires_at IS NOT NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS localwebauthn_active_grant_user_idx
  ON localwebauthn_enrollment_grants(user_id)
  WHERE completed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS localwebauthn_grant_expiry_idx
  ON localwebauthn_enrollment_grants(expires_at, completed_at, revoked_at);

CREATE TABLE IF NOT EXISTS localwebauthn_challenges (
  id_hash BYTEA PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('registration', 'authentication')),
  challenge TEXT NOT NULL,
  user_id TEXT,
  grant_id TEXT REFERENCES localwebauthn_enrollment_grants(id),
  authorization_session_hash BYTEA,
  expires_at BIGINT NOT NULL,
  consumed_at BIGINT,
  created_at BIGINT NOT NULL,
  CHECK (octet_length(id_hash) = 32),
  CHECK (
    kind = 'authentication'
    OR user_id IS NOT NULL
  ),
  CHECK (
    (grant_id IS NULL OR authorization_session_hash IS NULL)
    AND (kind = 'registration' OR (grant_id IS NULL AND authorization_session_hash IS NULL))
  )
);

CREATE INDEX IF NOT EXISTS localwebauthn_challenge_expiry_idx
  ON localwebauthn_challenges(expires_at, consumed_at);

CREATE TABLE IF NOT EXISTS localwebauthn_credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  public_key BYTEA NOT NULL,
  counter BIGINT NOT NULL DEFAULT 0 CHECK (counter >= 0),
  transports_json TEXT NOT NULL DEFAULT '[]',
  device_type TEXT NOT NULL CHECK (device_type IN ('singleDevice', 'multiDevice')),
  backed_up BOOLEAN NOT NULL DEFAULT FALSE,
  label TEXT NOT NULL DEFAULT 'Passkey',
  created_at BIGINT NOT NULL,
  last_used_at BIGINT,
  revoked_at BIGINT
);

CREATE INDEX IF NOT EXISTS localwebauthn_credential_user_idx
  ON localwebauthn_credentials(user_id, revoked_at);

CREATE TABLE IF NOT EXISTS localwebauthn_sessions (
  id_hash BYTEA PRIMARY KEY,
  user_id TEXT NOT NULL,
  credential_id TEXT NOT NULL REFERENCES localwebauthn_credentials(id),
  authenticated_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  last_seen_at BIGINT NOT NULL,
  revoked_at BIGINT,
  CHECK (octet_length(id_hash) = 32),
  CHECK (expires_at > authenticated_at)
);

CREATE INDEX IF NOT EXISTS localwebauthn_session_user_idx
  ON localwebauthn_sessions(user_id, revoked_at, expires_at);
`;
function localWebAuthnSchemaStatements() {
  return LOCALWEBAUTHN_SCHEMA_SQL.split(";").map((statement) => statement.replace(/\s+/gu, " ").trim()).filter(Boolean);
}
function localWebAuthnMigrationStatements(now = Date.now()) {
  return [
    ...localWebAuthnSchemaStatements(),
    `INSERT INTO localwebauthn_migrations(version, applied_at)
     VALUES (${String(LOCALWEBAUTHN_SCHEMA_VERSION)}, ${String(Math.trunc(now))})
     ON CONFLICT DO NOTHING`
  ];
}

export {
  LOCALWEBAUTHN_SCHEMA_VERSION,
  LOCALWEBAUTHN_SCHEMA_SQL,
  LOCALWEBAUTHN_POSTGRES_SCHEMA_SQL,
  localWebAuthnSchemaStatements,
  localWebAuthnMigrationStatements
};
