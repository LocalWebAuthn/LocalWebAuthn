/**
 * Current schema version.
 *
 * - `1` — the original tables. The only version ever released.
 * - `2` — everything machine credentials need, as one step: `kind` on
 *   credentials, credential heritage (`created_via`, `parent_credential_id`,
 *   `grant_id`, `approved_by_user_id`), per-ceremony kind scoping on challenges,
 *   `credential_kind` on enrollment grants with the pending-grant uniqueness
 *   re-scoped by it, and the DPoP proof-replay and nonce-slot tables. See
 *   {@link LOCALWEBAUTHN_MIGRATIONS}.
 *
 * Kept to two versions on purpose. The work arrived in several passes, each of
 * which briefly had its own version, but since `1` is the only version that was
 * ever published there is no database anywhere at an intermediate one — so
 * collapsing them leaves one upgrade path to write, test and read instead of
 * four.
 */
export const LOCALWEBAUTHN_SCHEMA_VERSION = 2;

/**
 * The schema, as one script split on `;` by {@link localWebAuthnSchemaStatements}.
 *
 * **No `--` comments.** The splitter collapses whitespace, which joins a comment
 * to the statement after it and comments the whole thing out — D1 then reports
 * "SQL code did not contain a statement". Explain things here instead.
 *
 * Two index choices worth knowing:
 *
 * - `localwebauthn_active_grant_user_idx` is unique per `(user_id, kind)`, not per
 *   user, so provisioning a deployment key does not silently revoke a person's
 *   in-flight enrollment link. `COALESCE(credential_kind, '')` is required
 *   because NULLs are distinct in a unique index on both engines — indexing the
 *   bare column would quietly drop the one-pending-grant invariant for the
 *   default kind, which is every grant a host that ignores kinds ever issues.
 * - `localwebauthn_credential_kind_idx` supports the kind-scoped last-credential
 *   guard and the kind-filtered revoke paths.
 * - `localwebauthn_credential_parent_idx` supports the descendant walk, which
 *   follows `parent_credential_id` downward and would otherwise scan.
 *
 * `parent_credential_id` is a real foreign key, which is only safe because
 * credentials are never deleted — cleanup does not touch them and revocation only
 * stamps `revoked_at`. So a heritage chain never breaks. `grant_id` and
 * `approved_by_user_id` are deliberately *not* foreign keys: grants are reaped, so
 * those two are copied facts about the past rather than live references.
 */
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
 *
 * `newTables` names the tables the version introduces. Their DDL is *not*
 * written here: {@link localWebAuthnUpgradeStatements} lifts the idempotent
 * `CREATE TABLE IF NOT EXISTS`, and every index over them, out of the full
 * schema in whichever dialect it was asked for. Adding a table therefore means
 * adding its name to this list — a table the schema creates but no entry claims
 * will exist on a fresh install and be missing on an upgraded one, which is a
 * failure only a fresh database would ever show.
 */
export const LOCALWEBAUTHN_MIGRATIONS: {
  version: number;
  statements: string[];
  /** Tables this version introduces; their DDL comes from the full schema. */
  newTables: string[];
}[] = [
  {
    version: 2,
    statements: [
      // Columns first: the grant index below is defined over `credential_kind`.
      'ALTER TABLE localwebauthn_credentials ADD COLUMN kind TEXT',
      // Heritage. SQLite permits a REFERENCES clause on ADD COLUMN provided the
      // default is NULL, which it is, so an upgraded database gets the same real
      // foreign key a fresh one does.
      'ALTER TABLE localwebauthn_credentials ADD COLUMN created_via TEXT',
      `ALTER TABLE localwebauthn_credentials
         ADD COLUMN parent_credential_id TEXT REFERENCES localwebauthn_credentials(id)`,
      'ALTER TABLE localwebauthn_credentials ADD COLUMN grant_id TEXT',
      'ALTER TABLE localwebauthn_credentials ADD COLUMN approved_by_user_id TEXT',
      'ALTER TABLE localwebauthn_challenges ADD COLUMN credential_kind TEXT',
      'ALTER TABLE localwebauthn_challenges ADD COLUMN allowed_credential_kinds TEXT',
      'ALTER TABLE localwebauthn_enrollment_grants ADD COLUMN credential_kind TEXT',
      `CREATE INDEX IF NOT EXISTS localwebauthn_credential_kind_idx
         ON localwebauthn_credentials(user_id, kind, revoked_at)`,
      `CREATE INDEX IF NOT EXISTS localwebauthn_credential_parent_idx
         ON localwebauthn_credentials(parent_credential_id)`,
      // Re-scope the pending-grant uniqueness from (user_id) to
      // (user_id, kind). Dropping first is required: an index cannot be
      // redefined in place, and the old one would keep enforcing one pending
      // grant per user regardless of kind.
      'DROP INDEX IF EXISTS localwebauthn_active_grant_user_idx',
      `CREATE UNIQUE INDEX IF NOT EXISTS localwebauthn_active_grant_user_idx
         ON localwebauthn_enrollment_grants(user_id, COALESCE(credential_kind, ''))
         WHERE completed_at IS NULL AND revoked_at IS NULL`,
    ],
    newTables: ['localwebauthn_dpop_proofs', 'localwebauthn_dpop_nonces'],
  },
];

/** The table a collapsed `CREATE TABLE` statement declares, else `null`. */
function declaredTable(statement: string): string | null {
  return /^CREATE TABLE IF NOT EXISTS (\w+)/u.exec(statement)?.[1] ?? null;
}

/** The table a collapsed `CREATE INDEX` statement is defined over, else `null`. */
function indexedTable(statement: string): string | null {
  return /^CREATE (?:UNIQUE )?INDEX IF NOT EXISTS \w+ ON (\w+)\s*\(/u.exec(statement)?.[1] ?? null;
}

/** Incremental statements for every entry above `fromVersion`, whitespace collapsed. */
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

/**
 * The `localwebauthn_migrations` DDL alone, in the requested dialect.
 *
 * The migration runner has to create this table before it can read its own stored
 * version, which means running one statement ahead of the schema. Deriving it from
 * the schema rather than repeating it is not tidiness: a hand-written copy declared
 * `applied_at INTEGER`, and PostgreSQL's `INTEGER` is 32-bit, so a millisecond
 * timestamp overflowed — and because the copy ran first, the correct `BIGINT`
 * version behind `IF NOT EXISTS` never applied. Only a fresh PostgreSQL database
 * showed it.
 */
export function localWebAuthnMigrationsTableStatement(
  dialect: 'sqlite' | 'postgres' = 'sqlite',
): string {
  const statements =
    dialect === 'postgres'
      ? localWebAuthnPostgresSchemaStatements()
      : localWebAuthnSchemaStatements();
  const statement = statements.find((candidate) =>
    /^CREATE TABLE IF NOT EXISTS localwebauthn_migrations\b/u.test(candidate),
  );
  if (!statement) {
    throw new Error('The schema no longer declares localwebauthn_migrations.');
  }
  return statement;
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
 * incremental upgrades above that version — plus, for every table those versions
 * declare in `newTables`, its `CREATE TABLE IF NOT EXISTS` and indexes lifted
 * from the full schema, which the incremental list cannot express portably.
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
  // Tables introduced above `fromVersion` come from the full schema's idempotent
  // `CREATE ... IF NOT EXISTS`, which the incremental list cannot express
  // portably: the two dialects spell the same table differently (BLOB/BYTEA,
  // INTEGER/BIGINT, STRICT). Columns still need explicit ALTERs, which are
  // dialect-neutral.
  const introduced = new Set(
    LOCALWEBAUTHN_MIGRATIONS.filter((entry) => entry.version > fromVersion).flatMap(
      (entry) => entry.newTables,
    ),
  );
  for (const table of introduced) {
    if (!schema.some((statement) => declaredTable(statement) === table)) {
      throw new Error(`A migration introduces ${table}, which the schema does not create.`);
    }
  }
  const tableStatements = schema.filter((statement) => {
    const table = declaredTable(statement) ?? indexedTable(statement);
    return table !== null && introduced.has(table);
  });
  return [...migrationStatements(fromVersion), ...tableStatements];
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
