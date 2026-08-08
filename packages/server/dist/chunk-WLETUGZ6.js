// src/schema.ts
var LOCALWEBAUTHN_SCHEMA_VERSION = 2;
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
  credential_kind TEXT,
  created_at INTEGER NOT NULL,
  CHECK (length(token_hash) = 32),
  CHECK (expires_at > created_at),
  CHECK (
    (session_hash IS NULL AND session_expires_at IS NULL)
    OR (session_hash IS NOT NULL AND session_expires_at IS NOT NULL)
  )
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS localwebauthn_active_grant_user_idx
  ON localwebauthn_enrollment_grants(user_id, COALESCE(credential_kind, ''))
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
  credential_kind TEXT,
  allowed_credential_kinds TEXT,
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
  kind TEXT,
  created_via TEXT,
  parent_credential_id TEXT REFERENCES localwebauthn_credentials(id),
  grant_id TEXT,
  approved_by_user_id TEXT,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS localwebauthn_credential_user_idx
  ON localwebauthn_credentials(user_id, revoked_at);

CREATE INDEX IF NOT EXISTS localwebauthn_credential_kind_idx
  ON localwebauthn_credentials(user_id, kind, revoked_at);

CREATE INDEX IF NOT EXISTS localwebauthn_credential_parent_idx
  ON localwebauthn_credentials(parent_credential_id);

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

CREATE TABLE IF NOT EXISTS localwebauthn_dpop_proofs (
  jti_hash BLOB PRIMARY KEY,
  expires_at INTEGER NOT NULL,
  CHECK (length(jti_hash) = 32)
) STRICT;

CREATE INDEX IF NOT EXISTS localwebauthn_dpop_expiry_idx
  ON localwebauthn_dpop_proofs(expires_at);

CREATE TABLE IF NOT EXISTS localwebauthn_dpop_nonces (
  slot INTEGER PRIMARY KEY,
  nonce TEXT NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS localwebauthn_dpop_nonce_expiry_idx
  ON localwebauthn_dpop_nonces(expires_at);

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
  credential_kind TEXT,
  created_at BIGINT NOT NULL,
  CHECK (octet_length(token_hash) = 32),
  CHECK (expires_at > created_at),
  CHECK (
    (session_hash IS NULL AND session_expires_at IS NULL)
    OR (session_hash IS NOT NULL AND session_expires_at IS NOT NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS localwebauthn_active_grant_user_idx
  ON localwebauthn_enrollment_grants(user_id, COALESCE(credential_kind, ''))
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
  credential_kind TEXT,
  allowed_credential_kinds TEXT,
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
  kind TEXT,
  created_via TEXT,
  parent_credential_id TEXT REFERENCES localwebauthn_credentials(id),
  grant_id TEXT,
  approved_by_user_id TEXT,
  created_at BIGINT NOT NULL,
  last_used_at BIGINT,
  revoked_at BIGINT
);

CREATE INDEX IF NOT EXISTS localwebauthn_credential_user_idx
  ON localwebauthn_credentials(user_id, revoked_at);

CREATE INDEX IF NOT EXISTS localwebauthn_credential_kind_idx
  ON localwebauthn_credentials(user_id, kind, revoked_at);

CREATE INDEX IF NOT EXISTS localwebauthn_credential_parent_idx
  ON localwebauthn_credentials(parent_credential_id);

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

CREATE TABLE IF NOT EXISTS localwebauthn_dpop_proofs (
  jti_hash BYTEA PRIMARY KEY,
  expires_at BIGINT NOT NULL,
  CHECK (octet_length(jti_hash) = 32)
);

CREATE INDEX IF NOT EXISTS localwebauthn_dpop_expiry_idx
  ON localwebauthn_dpop_proofs(expires_at);

CREATE TABLE IF NOT EXISTS localwebauthn_dpop_nonces (
  slot BIGINT PRIMARY KEY,
  nonce TEXT NOT NULL,
  expires_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS localwebauthn_dpop_nonce_expiry_idx
  ON localwebauthn_dpop_nonces(expires_at);
`;
var LOCALWEBAUTHN_MIGRATIONS = [
  {
    version: 2,
    statements: [
      // Columns first: the grant index below is defined over `credential_kind`.
      "ALTER TABLE localwebauthn_credentials ADD COLUMN kind TEXT",
      // Heritage. SQLite permits a REFERENCES clause on ADD COLUMN provided the
      // default is NULL, which it is, so an upgraded database gets the same real
      // foreign key a fresh one does.
      "ALTER TABLE localwebauthn_credentials ADD COLUMN created_via TEXT",
      `ALTER TABLE localwebauthn_credentials
         ADD COLUMN parent_credential_id TEXT REFERENCES localwebauthn_credentials(id)`,
      "ALTER TABLE localwebauthn_credentials ADD COLUMN grant_id TEXT",
      "ALTER TABLE localwebauthn_credentials ADD COLUMN approved_by_user_id TEXT",
      "ALTER TABLE localwebauthn_challenges ADD COLUMN credential_kind TEXT",
      "ALTER TABLE localwebauthn_challenges ADD COLUMN allowed_credential_kinds TEXT",
      "ALTER TABLE localwebauthn_enrollment_grants ADD COLUMN credential_kind TEXT",
      `CREATE INDEX IF NOT EXISTS localwebauthn_credential_kind_idx
         ON localwebauthn_credentials(user_id, kind, revoked_at)`,
      `CREATE INDEX IF NOT EXISTS localwebauthn_credential_parent_idx
         ON localwebauthn_credentials(parent_credential_id)`,
      // Re-scope the pending-grant uniqueness from (user_id) to
      // (user_id, kind). Dropping first is required: an index cannot be
      // redefined in place, and the old one would keep enforcing one pending
      // grant per user regardless of kind.
      "DROP INDEX IF EXISTS localwebauthn_active_grant_user_idx",
      `CREATE UNIQUE INDEX IF NOT EXISTS localwebauthn_active_grant_user_idx
         ON localwebauthn_enrollment_grants(user_id, COALESCE(credential_kind, ''))
         WHERE completed_at IS NULL AND revoked_at IS NULL`
      // `localwebauthn_dpop_proofs` and `localwebauthn_dpop_nonces` need no entry
      // here: they are new tables, so the idempotent `CREATE TABLE IF NOT EXISTS`
      // lifted out of the full schema by `localWebAuthnUpgradeStatements` creates
      // them, in whichever dialect that schema is written for.
    ]
  }
];
function migrationStatements(fromVersion) {
  return LOCALWEBAUTHN_MIGRATIONS.filter((entry) => entry.version > fromVersion).flatMap(
    (entry) => entry.statements.map((statement) => statement.replace(/\s+/gu, " ").trim())
  );
}
function localWebAuthnSchemaStatements() {
  return LOCALWEBAUTHN_SCHEMA_SQL.split(";").map((statement) => statement.replace(/\s+/gu, " ").trim()).filter(Boolean);
}
function localWebAuthnMigrationsTableStatement(dialect = "sqlite") {
  const statements = dialect === "postgres" ? localWebAuthnPostgresSchemaStatements() : localWebAuthnSchemaStatements();
  const statement = statements.find(
    (candidate) => /^CREATE TABLE IF NOT EXISTS localwebauthn_migrations\b/u.test(candidate)
  );
  if (!statement) {
    throw new Error("The schema no longer declares localwebauthn_migrations.");
  }
  return statement;
}
function localWebAuthnPostgresSchemaStatements() {
  return LOCALWEBAUTHN_POSTGRES_SCHEMA_SQL.split(";").map((statement) => statement.replace(/\s+/gu, " ").trim()).filter(Boolean);
}
function localWebAuthnUpgradeStatements(fromVersion, dialect = "sqlite") {
  const schema = dialect === "postgres" ? localWebAuthnPostgresSchemaStatements() : localWebAuthnSchemaStatements();
  if (fromVersion <= 0) {
    return schema;
  }
  if (fromVersion >= LOCALWEBAUTHN_SCHEMA_VERSION) {
    return [];
  }
  const newTables = schema.filter(
    (statement) => /^CREATE (TABLE|INDEX|UNIQUE INDEX) IF NOT EXISTS localwebauthn_dpop/u.test(statement)
  );
  return [...migrationStatements(fromVersion), ...newTables];
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
  LOCALWEBAUTHN_MIGRATIONS,
  localWebAuthnSchemaStatements,
  localWebAuthnMigrationsTableStatement,
  localWebAuthnPostgresSchemaStatements,
  localWebAuthnUpgradeStatements,
  localWebAuthnMigrationStatements
};
