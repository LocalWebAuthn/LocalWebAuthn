/**
 * Current schema version.
 *
 * - `1` — the original tables.
 * - `2` — credential `kind`, per-ceremony kind scoping on challenges, and the
 *   DPoP proof-replay cache. See {@link LOCALWEBAUTHN_MIGRATIONS}.
 */
export const LOCALWEBAUTHN_SCHEMA_VERSION = 2;

export const LOCALWEBAUTHN_SCHEMA_SQL = `
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
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS localwebauthn_credential_user_idx
  ON localwebauthn_credentials(user_id, revoked_at);

CREATE INDEX IF NOT EXISTS localwebauthn_credential_kind_idx
  ON localwebauthn_credentials(user_id, kind, revoked_at);

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

CREATE TABLE IF NOT EXISTS localwebauthn_transaction_guard (
  value INTEGER NOT NULL CHECK (value = 1)
) STRICT;
`;

/**
 * The same logical schema as {@link LOCALWEBAUTHN_SCHEMA_SQL}, rendered for
 * PostgreSQL. Differences are all engine spelling, not structure:
 *
 * - `BLOB` becomes `BYTEA`, and `length()` becomes `octet_length()`.
 * - Millisecond timestamps use `BIGINT`. node-postgres returns those as
 *   strings, which the row mappers coerce back to numbers.
 * - `backed_up` is a real `BOOLEAN` rather than a `0`/`1` integer.
 * - `STRICT` is dropped; PostgreSQL is already strictly typed.
 * - `localwebauthn_transaction_guard` is omitted. It exists only so the D1
 *   adapter can fail a batch mid-flight; PostgreSQL has real transactions.
 */
export const LOCALWEBAUTHN_POSTGRES_SCHEMA_SQL = `
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
  created_at BIGINT NOT NULL,
  last_used_at BIGINT,
  revoked_at BIGINT
);

CREATE INDEX IF NOT EXISTS localwebauthn_credential_user_idx
  ON localwebauthn_credentials(user_id, revoked_at);

CREATE INDEX IF NOT EXISTS localwebauthn_credential_kind_idx
  ON localwebauthn_credentials(user_id, kind, revoked_at);

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
`;

/**
 * Incremental upgrades, applied in order for any stored version below
 * {@link LOCALWEBAUTHN_SCHEMA_VERSION}.
 *
 * A fresh database runs {@link LOCALWEBAUTHN_SCHEMA_SQL} instead, which already
 * contains everything these statements add — so each entry exists only to bring
 * an *existing* installation forward. `CREATE TABLE IF NOT EXISTS` cannot add a
 * column, which is why this list is needed at all.
 *
 * Statements must be idempotent-by-gating rather than idempotent-by-syntax:
 * SQLite has no `ADD COLUMN IF NOT EXISTS`, so correctness comes from only
 * running an entry when the stored version is below it.
 *
 * No entry adds a `CHECK` constraint. SQLite cannot add one to an existing
 * table, and a fresh install must not end up with constraints an upgraded
 * install lacks — the two would diverge and only one of them would be tested.
 * Constraints that would otherwise live in the schema are enforced in the
 * service layer instead.
 */
export const LOCALWEBAUTHN_MIGRATIONS: { version: number; statements: string[] }[] = [
  {
    version: 2,
    statements: [
      'ALTER TABLE localwebauthn_credentials ADD COLUMN kind TEXT',
      'ALTER TABLE localwebauthn_challenges ADD COLUMN credential_kind TEXT',
      'ALTER TABLE localwebauthn_challenges ADD COLUMN allowed_credential_kinds TEXT',
      `CREATE INDEX IF NOT EXISTS localwebauthn_credential_kind_idx
         ON localwebauthn_credentials(user_id, kind, revoked_at)`,
    ],
  },
];

/** Statements from {@link LOCALWEBAUTHN_MIGRATIONS} for engines whose `dpop_proofs` DDL differs. */
function migrationStatements(fromVersion: number): string[] {
  return LOCALWEBAUTHN_MIGRATIONS.filter((entry) => entry.version > fromVersion).flatMap((entry) =>
    entry.statements.map((statement) => statement.replace(/\s+/gu, ' ').trim()),
  );
}

export function localWebAuthnSchemaStatements(): string[] {
  return LOCALWEBAUTHN_SCHEMA_SQL.split(';')
    .map((statement) => statement.replace(/\s+/gu, ' ').trim())
    .filter(Boolean);
}

export function localWebAuthnPostgresSchemaStatements(): string[] {
  return LOCALWEBAUTHN_POSTGRES_SCHEMA_SQL.split(';')
    .map((statement) => statement.replace(/\s+/gu, ' ').trim())
    .filter(Boolean);
}

/**
 * The DDL to bring a database at `fromVersion` up to
 * {@link LOCALWEBAUTHN_SCHEMA_VERSION}.
 *
 * `fromVersion` of `0` means "no `localwebauthn_migrations` row", i.e. a fresh
 * database, and yields the full schema. Anything else yields only the
 * incremental upgrades above that version — plus, for a v1 database, the
 * `CREATE TABLE IF NOT EXISTS` for tables introduced after v1, which the
 * incremental list cannot express portably.
 *
 * Returns an empty array when the database is already current.
 */
export function localWebAuthnUpgradeStatements(
  fromVersion: number,
  dialect: 'sqlite' | 'postgres' = 'sqlite',
): string[] {
  const schema =
    dialect === 'postgres'
      ? localWebAuthnPostgresSchemaStatements()
      : localWebAuthnSchemaStatements();
  if (fromVersion <= 0) {
    return schema;
  }
  if (fromVersion >= LOCALWEBAUTHN_SCHEMA_VERSION) {
    return [];
  }
  // Tables added after v1 are created by their `CREATE TABLE IF NOT EXISTS`
  // from the full schema; columns need the explicit ALTERs.
  const newTables = schema.filter((statement) =>
    /^CREATE (TABLE|INDEX|UNIQUE INDEX) IF NOT EXISTS localwebauthn_dpop/u.test(statement),
  );
  return [...migrationStatements(fromVersion), ...newTables];
}

/**
 * Full schema plus the version stamp, for engines that cannot read the stored
 * version before deciding what to run (D1's `migrateD1` batches blind).
 *
 * Safe on a v1 database only because the ALTERs are appended by
 * {@link localWebAuthnUpgradeStatements}; callers that can read the stored
 * version should prefer that function.
 */
export function localWebAuthnMigrationStatements(now = Date.now()): string[] {
  return [
    ...localWebAuthnSchemaStatements(),
    `INSERT INTO localwebauthn_migrations(version, applied_at)
     VALUES (${String(LOCALWEBAUTHN_SCHEMA_VERSION)}, ${String(Math.trunc(now))})
     ON CONFLICT DO NOTHING`,
  ];
}
