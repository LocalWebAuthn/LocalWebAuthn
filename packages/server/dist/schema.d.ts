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
declare const LOCALWEBAUTHN_SCHEMA_VERSION = 2;
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
declare const LOCALWEBAUTHN_SCHEMA_SQL = "\nCREATE TABLE IF NOT EXISTS localwebauthn_migrations (\n  version INTEGER PRIMARY KEY,\n  applied_at INTEGER NOT NULL\n) STRICT;\n\nCREATE TABLE IF NOT EXISTS localwebauthn_enrollment_grants (\n  id TEXT PRIMARY KEY,\n  user_id TEXT NOT NULL,\n  token_hash BLOB NOT NULL UNIQUE,\n  expires_at INTEGER NOT NULL,\n  token_consumed_at INTEGER,\n  session_hash BLOB,\n  session_expires_at INTEGER,\n  completed_at INTEGER,\n  revoked_at INTEGER,\n  approved_by_user_id TEXT,\n  credential_kind TEXT,\n  created_at INTEGER NOT NULL,\n  CHECK (length(token_hash) = 32),\n  CHECK (expires_at > created_at),\n  CHECK (\n    (session_hash IS NULL AND session_expires_at IS NULL)\n    OR (session_hash IS NOT NULL AND session_expires_at IS NOT NULL)\n  )\n) STRICT;\n\nCREATE UNIQUE INDEX IF NOT EXISTS localwebauthn_active_grant_user_idx\n  ON localwebauthn_enrollment_grants(user_id, COALESCE(credential_kind, ''))\n  WHERE completed_at IS NULL AND revoked_at IS NULL;\n\nCREATE INDEX IF NOT EXISTS localwebauthn_grant_expiry_idx\n  ON localwebauthn_enrollment_grants(expires_at, completed_at, revoked_at);\n\nCREATE TABLE IF NOT EXISTS localwebauthn_challenges (\n  id_hash BLOB PRIMARY KEY,\n  kind TEXT NOT NULL CHECK (kind IN ('registration', 'authentication')),\n  challenge TEXT NOT NULL,\n  user_id TEXT,\n  grant_id TEXT REFERENCES localwebauthn_enrollment_grants(id),\n  authorization_session_hash BLOB,\n  credential_kind TEXT,\n  allowed_credential_kinds TEXT,\n  expires_at INTEGER NOT NULL,\n  consumed_at INTEGER,\n  created_at INTEGER NOT NULL,\n  CHECK (length(id_hash) = 32),\n  CHECK (\n    kind = 'authentication'\n    OR user_id IS NOT NULL\n  ),\n  CHECK (\n    (grant_id IS NULL OR authorization_session_hash IS NULL)\n    AND (kind = 'registration' OR (grant_id IS NULL AND authorization_session_hash IS NULL))\n  )\n) STRICT;\n\nCREATE INDEX IF NOT EXISTS localwebauthn_challenge_expiry_idx\n  ON localwebauthn_challenges(expires_at, consumed_at);\n\nCREATE TABLE IF NOT EXISTS localwebauthn_credentials (\n  id TEXT PRIMARY KEY,\n  user_id TEXT NOT NULL,\n  public_key BLOB NOT NULL,\n  counter INTEGER NOT NULL DEFAULT 0 CHECK (counter >= 0),\n  transports_json TEXT NOT NULL DEFAULT '[]',\n  device_type TEXT NOT NULL CHECK (device_type IN ('singleDevice', 'multiDevice')),\n  backed_up INTEGER NOT NULL DEFAULT 0 CHECK (backed_up IN (0, 1)),\n  label TEXT NOT NULL DEFAULT 'Passkey',\n  kind TEXT,\n  created_via TEXT,\n  parent_credential_id TEXT REFERENCES localwebauthn_credentials(id),\n  grant_id TEXT,\n  approved_by_user_id TEXT,\n  created_at INTEGER NOT NULL,\n  last_used_at INTEGER,\n  revoked_at INTEGER\n) STRICT;\n\nCREATE INDEX IF NOT EXISTS localwebauthn_credential_user_idx\n  ON localwebauthn_credentials(user_id, revoked_at);\n\nCREATE INDEX IF NOT EXISTS localwebauthn_credential_kind_idx\n  ON localwebauthn_credentials(user_id, kind, revoked_at);\n\nCREATE INDEX IF NOT EXISTS localwebauthn_credential_parent_idx\n  ON localwebauthn_credentials(parent_credential_id);\n\nCREATE TABLE IF NOT EXISTS localwebauthn_sessions (\n  id_hash BLOB PRIMARY KEY,\n  user_id TEXT NOT NULL,\n  credential_id TEXT NOT NULL REFERENCES localwebauthn_credentials(id),\n  authenticated_at INTEGER NOT NULL,\n  expires_at INTEGER NOT NULL,\n  last_seen_at INTEGER NOT NULL,\n  revoked_at INTEGER,\n  CHECK (length(id_hash) = 32),\n  CHECK (expires_at > authenticated_at)\n) STRICT;\n\nCREATE INDEX IF NOT EXISTS localwebauthn_session_user_idx\n  ON localwebauthn_sessions(user_id, revoked_at, expires_at);\n\nCREATE TABLE IF NOT EXISTS localwebauthn_dpop_proofs (\n  jti_hash BLOB PRIMARY KEY,\n  expires_at INTEGER NOT NULL,\n  CHECK (length(jti_hash) = 32)\n) STRICT;\n\nCREATE INDEX IF NOT EXISTS localwebauthn_dpop_expiry_idx\n  ON localwebauthn_dpop_proofs(expires_at);\n\nCREATE TABLE IF NOT EXISTS localwebauthn_dpop_nonces (\n  slot INTEGER PRIMARY KEY,\n  nonce TEXT NOT NULL,\n  expires_at INTEGER NOT NULL\n) STRICT;\n\nCREATE INDEX IF NOT EXISTS localwebauthn_dpop_nonce_expiry_idx\n  ON localwebauthn_dpop_nonces(expires_at);\n\nCREATE TABLE IF NOT EXISTS localwebauthn_transaction_guard (\n  value INTEGER NOT NULL CHECK (value = 1)\n) STRICT;\n";
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
declare const LOCALWEBAUTHN_POSTGRES_SCHEMA_SQL = "\nCREATE TABLE IF NOT EXISTS localwebauthn_migrations (\n  version INTEGER PRIMARY KEY,\n  applied_at BIGINT NOT NULL\n);\n\nCREATE TABLE IF NOT EXISTS localwebauthn_enrollment_grants (\n  id TEXT PRIMARY KEY,\n  user_id TEXT NOT NULL,\n  token_hash BYTEA NOT NULL UNIQUE,\n  expires_at BIGINT NOT NULL,\n  token_consumed_at BIGINT,\n  session_hash BYTEA,\n  session_expires_at BIGINT,\n  completed_at BIGINT,\n  revoked_at BIGINT,\n  approved_by_user_id TEXT,\n  credential_kind TEXT,\n  created_at BIGINT NOT NULL,\n  CHECK (octet_length(token_hash) = 32),\n  CHECK (expires_at > created_at),\n  CHECK (\n    (session_hash IS NULL AND session_expires_at IS NULL)\n    OR (session_hash IS NOT NULL AND session_expires_at IS NOT NULL)\n  )\n);\n\nCREATE UNIQUE INDEX IF NOT EXISTS localwebauthn_active_grant_user_idx\n  ON localwebauthn_enrollment_grants(user_id, COALESCE(credential_kind, ''))\n  WHERE completed_at IS NULL AND revoked_at IS NULL;\n\nCREATE INDEX IF NOT EXISTS localwebauthn_grant_expiry_idx\n  ON localwebauthn_enrollment_grants(expires_at, completed_at, revoked_at);\n\nCREATE TABLE IF NOT EXISTS localwebauthn_challenges (\n  id_hash BYTEA PRIMARY KEY,\n  kind TEXT NOT NULL CHECK (kind IN ('registration', 'authentication')),\n  challenge TEXT NOT NULL,\n  user_id TEXT,\n  grant_id TEXT REFERENCES localwebauthn_enrollment_grants(id),\n  authorization_session_hash BYTEA,\n  credential_kind TEXT,\n  allowed_credential_kinds TEXT,\n  expires_at BIGINT NOT NULL,\n  consumed_at BIGINT,\n  created_at BIGINT NOT NULL,\n  CHECK (octet_length(id_hash) = 32),\n  CHECK (\n    kind = 'authentication'\n    OR user_id IS NOT NULL\n  ),\n  CHECK (\n    (grant_id IS NULL OR authorization_session_hash IS NULL)\n    AND (kind = 'registration' OR (grant_id IS NULL AND authorization_session_hash IS NULL))\n  )\n);\n\nCREATE INDEX IF NOT EXISTS localwebauthn_challenge_expiry_idx\n  ON localwebauthn_challenges(expires_at, consumed_at);\n\nCREATE TABLE IF NOT EXISTS localwebauthn_credentials (\n  id TEXT PRIMARY KEY,\n  user_id TEXT NOT NULL,\n  public_key BYTEA NOT NULL,\n  counter BIGINT NOT NULL DEFAULT 0 CHECK (counter >= 0),\n  transports_json TEXT NOT NULL DEFAULT '[]',\n  device_type TEXT NOT NULL CHECK (device_type IN ('singleDevice', 'multiDevice')),\n  backed_up BOOLEAN NOT NULL DEFAULT FALSE,\n  label TEXT NOT NULL DEFAULT 'Passkey',\n  kind TEXT,\n  created_via TEXT,\n  parent_credential_id TEXT REFERENCES localwebauthn_credentials(id),\n  grant_id TEXT,\n  approved_by_user_id TEXT,\n  created_at BIGINT NOT NULL,\n  last_used_at BIGINT,\n  revoked_at BIGINT\n);\n\nCREATE INDEX IF NOT EXISTS localwebauthn_credential_user_idx\n  ON localwebauthn_credentials(user_id, revoked_at);\n\nCREATE INDEX IF NOT EXISTS localwebauthn_credential_kind_idx\n  ON localwebauthn_credentials(user_id, kind, revoked_at);\n\nCREATE INDEX IF NOT EXISTS localwebauthn_credential_parent_idx\n  ON localwebauthn_credentials(parent_credential_id);\n\nCREATE TABLE IF NOT EXISTS localwebauthn_sessions (\n  id_hash BYTEA PRIMARY KEY,\n  user_id TEXT NOT NULL,\n  credential_id TEXT NOT NULL REFERENCES localwebauthn_credentials(id),\n  authenticated_at BIGINT NOT NULL,\n  expires_at BIGINT NOT NULL,\n  last_seen_at BIGINT NOT NULL,\n  revoked_at BIGINT,\n  CHECK (octet_length(id_hash) = 32),\n  CHECK (expires_at > authenticated_at)\n);\n\nCREATE INDEX IF NOT EXISTS localwebauthn_session_user_idx\n  ON localwebauthn_sessions(user_id, revoked_at, expires_at);\n\nCREATE TABLE IF NOT EXISTS localwebauthn_dpop_proofs (\n  jti_hash BYTEA PRIMARY KEY,\n  expires_at BIGINT NOT NULL,\n  CHECK (octet_length(jti_hash) = 32)\n);\n\nCREATE INDEX IF NOT EXISTS localwebauthn_dpop_expiry_idx\n  ON localwebauthn_dpop_proofs(expires_at);\n\nCREATE TABLE IF NOT EXISTS localwebauthn_dpop_nonces (\n  slot BIGINT PRIMARY KEY,\n  nonce TEXT NOT NULL,\n  expires_at BIGINT NOT NULL\n);\n\nCREATE INDEX IF NOT EXISTS localwebauthn_dpop_nonce_expiry_idx\n  ON localwebauthn_dpop_nonces(expires_at);\n";
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
declare const LOCALWEBAUTHN_MIGRATIONS: {
    version: number;
    statements: string[];
    /** Tables this version introduces; their DDL comes from the full schema. */
    newTables: string[];
}[];
declare function localWebAuthnSchemaStatements(): string[];
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
declare function localWebAuthnMigrationsTableStatement(dialect?: 'sqlite' | 'postgres'): string;
declare function localWebAuthnPostgresSchemaStatements(): string[];
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
declare function localWebAuthnUpgradeStatements(fromVersion: number, dialect?: 'sqlite' | 'postgres'): string[];

export { LOCALWEBAUTHN_MIGRATIONS, LOCALWEBAUTHN_POSTGRES_SCHEMA_SQL, LOCALWEBAUTHN_SCHEMA_SQL, LOCALWEBAUTHN_SCHEMA_VERSION, localWebAuthnMigrationsTableStatement, localWebAuthnPostgresSchemaStatements, localWebAuthnSchemaStatements, localWebAuthnUpgradeStatements };
