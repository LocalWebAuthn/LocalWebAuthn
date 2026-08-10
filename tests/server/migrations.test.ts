/**
 * The version-1 → version-2 upgrade, against the real released schema.
 *
 * `V1_SCHEMA_SQL` below is the literal `LOCALWEBAUTHN_SCHEMA_SQL` from the last
 * commit before machine credentials existed, so this is what a deployed database
 * actually looks like — not a reconstruction from the current source. Version 1
 * is the only version ever published, which is why there is exactly one upgrade
 * path to test.
 */

import Database from 'better-sqlite3';
import { Miniflare } from 'miniflare';
import pg from 'pg';
import { afterAll, describe, expect, it } from 'vitest';

import {
  migratePostgres,
  type PostgresPool,
  PostgresLocalWebAuthnStore,
} from '../../packages/server/src/postgres.js';

import {
  type D1DatabaseLike,
  D1LocalWebAuthnStore,
  migrateD1,
} from '../../packages/server/src/d1.js';
import {
  LOCALWEBAUTHN_MIGRATIONS,
  LOCALWEBAUTHN_SCHEMA_VERSION,
  localWebAuthnUpgradeStatements,
} from '../../packages/server/src/schema.js';
import { migrateSqlite, SqliteLocalWebAuthnStore } from '../../packages/server/src/sqlite.js';

const V1_SCHEMA_SQL = `
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

const now = 1_000_000;

const postgresUrl = process.env.LOCALWEBAUTHN_TEST_POSTGRES_URL;

/** PostgreSQL runs against a real server; skip when none is reachable. */
async function postgresIsReachable(): Promise<boolean> {
  if (!postgresUrl) {
    return false;
  }
  const pool = new pg.Pool({ connectionString: postgresUrl, connectionTimeoutMillis: 2000 });
  try {
    await pool.query('SELECT 1');
    return true;
  } catch {
    return false;
  } finally {
    await pool.end().catch(() => undefined);
  }
}

const postgresReachable = await postgresIsReachable();

// CI sets this so an unreachable server fails rather than silently skipping.
if (process.env.LOCALWEBAUTHN_REQUIRE_POSTGRES === '1' && !postgresReachable) {
  throw new Error('LOCALWEBAUTHN_REQUIRE_POSTGRES=1 but no PostgreSQL server was reachable.');
}

type SqliteHandle = ReturnType<typeof Database>;

function columnNames(database: SqliteHandle, table: string): string[] {
  return (database.pragma(`table_info(${table})`) as { name: string }[])
    .map((column) => column.name)
    .sort();
}

function objectNames(database: SqliteHandle, type: 'table' | 'index'): string[] {
  return (
    database
      .prepare(`SELECT name FROM sqlite_master WHERE type = ? AND name LIKE 'localwebauthn%'`)
      .all(type) as { name: string }[]
  )
    .map((row) => row.name)
    .sort();
}

function indexSql(database: SqliteHandle, name: string): string {
  const row = database
    .prepare(`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?`)
    .get(name) as { sql: string | null } | undefined;
  return (row?.sql ?? '').replace(/\s+/gu, ' ').trim();
}

/** A version-1 database holding a grant, a credential and a session. */
function v1Database(): SqliteHandle {
  const database = new Database(':memory:');
  database.exec('PRAGMA foreign_keys = ON');
  database.exec(V1_SCHEMA_SQL);
  database
    .prepare('INSERT INTO localwebauthn_migrations(version, applied_at) VALUES (1, ?)')
    .run(now);
  database
    .prepare(
      `INSERT INTO localwebauthn_enrollment_grants(
         id, user_id, token_hash, expires_at, approved_by_user_id, created_at
       ) VALUES ('grant-1', 'user-1', ?, ?, 'admin-1', ?)`,
    )
    .run(new Uint8Array(32).fill(1), now + 10_000, now);
  database
    .prepare(
      `INSERT INTO localwebauthn_credentials(
         id, user_id, public_key, device_type, label, created_at
       ) VALUES ('credential-1', 'user-1', ?, 'multiDevice', 'Old passkey', ?)`,
    )
    .run(new Uint8Array(9).fill(9), now);
  database
    .prepare(
      `INSERT INTO localwebauthn_sessions(
         id_hash, user_id, credential_id, authenticated_at, expires_at, last_seen_at
       ) VALUES (?, 'user-1', 'credential-1', ?, ?, ?)`,
    )
    .run(new Uint8Array(32).fill(4), now, now + 10_000, now);
  return database;
}

function freshDatabase(): SqliteHandle {
  const database = new Database(':memory:');
  migrateSqlite(database, now);
  return database;
}

describe('version 1 to version 2', () => {
  it('reaches the current version', () => {
    const database = v1Database();
    migrateSqlite(database, now);
    const row = database
      .prepare('SELECT MAX(version) AS version FROM localwebauthn_migrations')
      .get() as {
      version: number;
    };
    expect(row.version).toBe(LOCALWEBAUTHN_SCHEMA_VERSION);
    database.close();
  });

  it('ends up with the same tables, columns and indexes as a fresh install', () => {
    const upgraded = v1Database();
    migrateSqlite(upgraded, now);
    const fresh = freshDatabase();

    expect(objectNames(upgraded, 'table')).toEqual(objectNames(fresh, 'table'));
    expect(objectNames(upgraded, 'index')).toEqual(objectNames(fresh, 'index'));

    // Column *sets*, not order: `ALTER TABLE ADD COLUMN` appends, while the fresh
    // schema declares new columns where they read best. Order carries no meaning
    // in SQL, and matching it would mean declaring every future column last.
    for (const table of objectNames(fresh, 'table')) {
      expect(columnNames(upgraded, table), table).toEqual(columnNames(fresh, table));
    }

    // Indexes are created by identical DDL on both paths, so these do match
    // exactly — including the re-scoped grant index, which is the one statement
    // that had to drop and recreate rather than being additive.
    for (const index of objectNames(fresh, 'index')) {
      expect(indexSql(upgraded, index), index).toBe(indexSql(fresh, index));
    }
    expect(indexSql(fresh, 'localwebauthn_active_grant_user_idx')).toContain(
      "COALESCE(credential_kind, '')",
    );

    upgraded.close();
    fresh.close();
  });

  it('preserves existing rows, with the new columns null', () => {
    const database = v1Database();
    migrateSqlite(database, now);

    const credential = database
      .prepare('SELECT label, kind FROM localwebauthn_credentials WHERE id = ?')
      .get('credential-1') as { label: string; kind: string | null };
    expect(credential).toEqual({ label: 'Old passkey', kind: null });

    const grant = database
      .prepare('SELECT id, credential_kind FROM localwebauthn_enrollment_grants WHERE id = ?')
      .get('grant-1') as { id: string; credential_kind: string | null };
    expect(grant).toEqual({ id: 'grant-1', credential_kind: null });

    database.close();
  });

  it('is idempotent', () => {
    const database = v1Database();
    migrateSqlite(database, now);
    // A second call must not re-run the ALTERs; SQLite has no
    // `ADD COLUMN IF NOT EXISTS`, so a duplicate would throw.
    expect(() => migrateSqlite(database, now)).not.toThrow();
    expect(() => migrateSqlite(database, now)).not.toThrow();
    database.close();
  });

  it('lifts a new version’s tables and their indexes out of the schema', () => {
    // The upgrade path cannot write dialect-specific DDL, so each version names
    // the tables it introduces and their real DDL is taken from the full schema.
    for (const dialect of ['sqlite', 'postgres'] as const) {
      const statements = localWebAuthnUpgradeStatements(1, dialect);
      for (const table of LOCALWEBAUTHN_MIGRATIONS.flatMap((entry) => entry.newTables)) {
        expect(statements, `${dialect} ${table}`).toContainEqual(
          expect.stringContaining(`CREATE TABLE IF NOT EXISTS ${table}`),
        );
      }
      expect(statements).toContainEqual(
        expect.stringContaining('ON localwebauthn_dpop_nonces(expires_at)'),
      );
    }
  });

  it('refuses a version that introduces a table the schema does not create', () => {
    // A typo here would otherwise produce a table on fresh installs and no table
    // on upgraded ones — the failure shape only a fresh database ever reveals.
    LOCALWEBAUTHN_MIGRATIONS.push({
      version: 99,
      statements: [],
      newTables: ['localwebauthn_typo'],
    });
    try {
      expect(() => localWebAuthnUpgradeStatements(1)).toThrow(/localwebauthn_typo/u);
    } finally {
      LOCALWEBAUTHN_MIGRATIONS.pop();
    }
  });

  it('leaves an upgraded database fully usable', async () => {
    const database = v1Database();
    migrateSqlite(database, now);
    const store = new SqliteLocalWebAuthnStore(database);

    // The features the upgrade exists for, exercised against migrated tables.
    expect(await store.claimDpopProof(new Uint8Array(32).fill(5), now + 60_000)).toBe(true);
    expect(await store.claimDpopNonce(1, 'nonce-1', now + 60_000)).toBe('nonce-1');
    await expect(store.listCredentials('user-1')).resolves.toMatchObject([{ kind: null }]);

    // One pending grant per (user, kind): a differently kinded grant coexists with
    // the migrated one, which the v1 index would have refused.
    await store.replaceEnrollmentGrant({
      id: 'grant-service',
      userId: 'user-1',
      tokenHash: new Uint8Array(32).fill(2),
      expiresAt: now + 10_000,
      approvedByUserId: null,
      credentialKind: 'service',
      createdAt: now,
    });
    const pending = database
      .prepare(
        `SELECT COUNT(*) AS count FROM localwebauthn_enrollment_grants
         WHERE completed_at IS NULL AND revoked_at IS NULL`,
      )
      .get() as { count: number };
    expect(pending.count).toBe(2);

    database.close();
  });
});

/**
 * The same v1→v2 upgrade on Cloudflare D1, which is the one that was broken:
 * `migrateD1` ran the current full schema blind, so a released v1 database never
 * got its `ALTER TABLE`s and the first index over a v2-only column failed. D1 is
 * SQLite, so the literal released DDL above loads unchanged.
 */
const miniflares = new Set<Miniflare>();

afterAll(async () => {
  await Promise.all([...miniflares].map((miniflare) => miniflare.dispose()));
  miniflares.clear();
});

async function emptyD1(): Promise<D1DatabaseLike> {
  const miniflare = new Miniflare({
    compatibilityDate: '2026-07-29',
    d1Databases: ['AUTH'],
    modules: true,
    script: 'export default { fetch() { return new Response("ok"); } }',
  });
  miniflares.add(miniflare);
  return (await miniflare.getD1Database('AUTH')) as unknown as D1DatabaseLike;
}

/** Statement list of a released v1 database, whitespace collapsed like the runners do. */
function v1Statements(): string[] {
  return V1_SCHEMA_SQL.split(';')
    .map((statement) => statement.replace(/\s+/gu, ' ').trim())
    .filter(Boolean);
}

async function d1ObjectNames(database: D1DatabaseLike, type: 'table' | 'index'): Promise<string[]> {
  const { results } = await database
    .prepare(`SELECT name FROM sqlite_master WHERE type = ? AND name LIKE 'localwebauthn%'`)
    .bind(type)
    .all<{ name: string }>();
  return results.map((row) => row.name).sort();
}

async function d1IndexSql(database: D1DatabaseLike, name: string): Promise<string> {
  const row = await database
    .prepare(`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?`)
    .bind(name)
    .first<{ sql: string | null }>();
  return (row?.sql ?? '').replace(/\s+/gu, ' ').trim();
}

/** A released v1 D1 database holding a grant, a credential and a session. */
async function v1D1Database(): Promise<D1DatabaseLike> {
  const database = await emptyD1();
  for (const statement of v1Statements()) {
    await database.prepare(statement).run();
  }
  await database
    .prepare('INSERT INTO localwebauthn_migrations(version, applied_at) VALUES (1, ?)')
    .bind(now)
    .run();
  await database
    .prepare(
      `INSERT INTO localwebauthn_enrollment_grants(
         id, user_id, token_hash, expires_at, approved_by_user_id, created_at
       ) VALUES ('grant-1', 'user-1', ?, ?, 'admin-1', ?)`,
    )
    .bind(new Uint8Array(32).fill(1), now + 10_000, now)
    .run();
  await database
    .prepare(
      `INSERT INTO localwebauthn_credentials(
         id, user_id, public_key, device_type, label, created_at
       ) VALUES ('credential-1', 'user-1', ?, 'multiDevice', 'Old passkey', ?)`,
    )
    .bind(new Uint8Array(9).fill(9), now)
    .run();
  await database
    .prepare(
      `INSERT INTO localwebauthn_sessions(
         id_hash, user_id, credential_id, authenticated_at, expires_at, last_seen_at
       ) VALUES (?, 'user-1', 'credential-1', ?, ?, ?)`,
    )
    .bind(new Uint8Array(32).fill(4), now, now + 10_000, now)
    .run();
  return database;
}

async function d1Version(database: D1DatabaseLike): Promise<number> {
  const row = await database
    .prepare('SELECT MAX(version) AS version FROM localwebauthn_migrations')
    .first<{ version: number | null }>();
  return row?.version ?? 0;
}

describe('D1 version 1 to version 2', () => {
  it('reaches the current version instead of failing on a v2-only index', async () => {
    // On the previous implementation this rejected: `CREATE INDEX ... (user_id,
    // kind, ...)` ran against a v1 table with no `kind` column.
    const database = await v1D1Database();
    await migrateD1(database, now);
    expect(await d1Version(database)).toBe(LOCALWEBAUTHN_SCHEMA_VERSION);
  });

  it('ends up with the same tables and indexes as a fresh install', async () => {
    const upgraded = await v1D1Database();
    await migrateD1(upgraded, now);
    const fresh = await emptyD1();
    await migrateD1(fresh, now);

    expect(await d1ObjectNames(upgraded, 'table')).toEqual(await d1ObjectNames(fresh, 'table'));
    expect(await d1ObjectNames(upgraded, 'index')).toEqual(await d1ObjectNames(fresh, 'index'));
    // The re-scoped grant index is the one statement that had to drop and recreate.
    expect(await d1IndexSql(upgraded, 'localwebauthn_active_grant_user_idx')).toBe(
      await d1IndexSql(fresh, 'localwebauthn_active_grant_user_idx'),
    );
    expect(await d1IndexSql(fresh, 'localwebauthn_active_grant_user_idx')).toContain(
      "COALESCE(credential_kind, '')",
    );
  });

  it('adds the v2 columns and preserves existing rows with them null', async () => {
    const database = await v1D1Database();
    await migrateD1(database, now);

    // Selecting the v2 columns would throw if the ALTERs had not run.
    const credential = await database
      .prepare(
        `SELECT label, kind, created_via, parent_credential_id, grant_id, approved_by_user_id
         FROM localwebauthn_credentials WHERE id = 'credential-1'`,
      )
      .first();
    expect(credential).toEqual({
      label: 'Old passkey',
      kind: null,
      created_via: null,
      parent_credential_id: null,
      grant_id: null,
      approved_by_user_id: null,
    });

    const grant = await database
      .prepare(
        `SELECT id, credential_kind FROM localwebauthn_enrollment_grants WHERE id = 'grant-1'`,
      )
      .first<{ id: string; credential_kind: string | null }>();
    expect(grant).toEqual({ id: 'grant-1', credential_kind: null });
  });

  it('is idempotent', async () => {
    const database = await v1D1Database();
    await migrateD1(database, now);
    await expect(migrateD1(database, now)).resolves.toBeUndefined();
    await expect(migrateD1(database, now)).resolves.toBeUndefined();
    expect(await d1Version(database)).toBe(LOCALWEBAUTHN_SCHEMA_VERSION);
  });

  it('leaves an upgraded database fully usable', async () => {
    const database = await v1D1Database();
    await migrateD1(database, now);
    const store = new D1LocalWebAuthnStore(database);

    // The features the upgrade exists for, against migrated tables.
    expect(await store.claimDpopProof(new Uint8Array(32).fill(5), now + 60_000)).toBe(true);
    expect(await store.claimDpopNonce(1, 'nonce-1', now + 60_000)).toBe('nonce-1');
    await expect(store.listCredentials('user-1')).resolves.toMatchObject([{ kind: null }]);
  });
});

/**
 * The literal released v1 PostgreSQL DDL, from `LOCALWEBAUTHN_POSTGRES_SCHEMA_SQL`
 * at the last commit before machine credentials. PostgreSQL's runner was already
 * version-aware, but "already correct" is a claim, and only a real v1 database
 * proves it — types included, which is where the `applied_at INTEGER` overflow
 * hid the first time.
 */
const V1_POSTGRES_SCHEMA_SQL = `
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

describe.skipIf(!postgresReachable)('PostgreSQL version 1 to version 2', () => {
  // Its own PostgreSQL schema, because this test drops and recreates tables while
  // `store-conformance.test.ts` is using the same server — and vitest runs test
  // files in parallel. Namespacing is what keeps that from being a coin flip.
  const NAMESPACE = 'lwa_migration_fixture';

  async function v1PostgresDatabase() {
    const setup = new pg.Pool({ connectionString: postgresUrl });
    try {
      await setup.query(`DROP SCHEMA IF EXISTS ${NAMESPACE} CASCADE`);
      await setup.query(`CREATE SCHEMA ${NAMESPACE}`);
    } finally {
      await setup.end();
    }
    // Every connection from this pool resolves unqualified names in the fixture
    // schema, so the released DDL below loads unchanged.
    const pool = new pg.Pool({
      connectionString: postgresUrl,
      options: `-c search_path=${NAMESPACE}`,
    });
    await pool.query(V1_POSTGRES_SCHEMA_SQL);
    await pool.query('INSERT INTO localwebauthn_migrations(version, applied_at) VALUES (1, $1)', [
      now,
    ]);
    await pool.query(
      `INSERT INTO localwebauthn_enrollment_grants(
         id, user_id, token_hash, expires_at, approved_by_user_id, created_at
       ) VALUES ('grant-1', 'user-1', $1, $2, 'admin-1', $3)`,
      [Buffer.alloc(32, 1), now + 10_000, now],
    );
    await pool.query(
      `INSERT INTO localwebauthn_credentials(
         id, user_id, public_key, device_type, label, created_at
       ) VALUES ('credential-1', 'user-1', $1, 'multiDevice', 'Old passkey', $2)`,
      [Buffer.alloc(9, 9), now],
    );
    await pool.query(
      `INSERT INTO localwebauthn_sessions(
         id_hash, user_id, credential_id, authenticated_at, expires_at, last_seen_at
       ) VALUES ($1, 'user-1', 'credential-1', $2, $3, $4)`,
      [Buffer.alloc(32, 4), now, now + 10_000, now],
    );
    return pool;
  }

  async function columns(pool: pg.Pool, table: string) {
    const result = await pool.query<{ column_name: string; data_type: string }>(
      `SELECT column_name, data_type FROM information_schema.columns
       WHERE table_schema = $1 AND table_name = $2 ORDER BY column_name`,
      [NAMESPACE, table],
    );
    return result.rows;
  }

  it('upgrades a literal v1 database, preserving rows and BIGINT timestamps', async () => {
    const pool = await v1PostgresDatabase();
    try {
      await migratePostgres(pool as unknown as PostgresPool, now);

      const version = await pool.query<{ version: string }>(
        'SELECT MAX(version) AS version FROM localwebauthn_migrations',
      );
      expect(Number(version.rows[0].version)).toBe(LOCALWEBAUTHN_SCHEMA_VERSION);

      // v2 columns exist, and the millisecond timestamps are BIGINT rather than
      // 32-bit INTEGER — the defect that only a fresh database revealed before.
      const credentialColumns = await columns(pool, 'localwebauthn_credentials');
      const names = credentialColumns.map((row) => row.column_name);
      expect(names).toContain('kind');
      expect(names).toContain('created_via');
      expect(names).toContain('parent_credential_id');
      expect(credentialColumns.find((row) => row.column_name === 'created_at')?.data_type).toBe(
        'bigint',
      );
      const migrationColumns = await columns(pool, 'localwebauthn_migrations');
      expect(migrationColumns.find((row) => row.column_name === 'applied_at')?.data_type).toBe(
        'bigint',
      );

      // The v1 rows survive, with the new columns null.
      const credential = await pool.query<{ label: string; kind: string | null }>(
        `SELECT label, kind FROM localwebauthn_credentials WHERE id = 'credential-1'`,
      );
      expect(credential.rows[0]).toEqual({ label: 'Old passkey', kind: null });

      // The tables and the re-scoped partial unique index the upgrade adds.
      const tables = await pool.query<{ tablename: string }>(
        `SELECT tablename FROM pg_tables WHERE schemaname = $1 ORDER BY tablename`,
        [NAMESPACE],
      );
      expect(tables.rows.map((row) => row.tablename)).toEqual([
        'localwebauthn_challenges',
        'localwebauthn_credentials',
        'localwebauthn_dpop_nonces',
        'localwebauthn_dpop_proofs',
        'localwebauthn_enrollment_grants',
        'localwebauthn_migrations',
        'localwebauthn_registration_fences',
        'localwebauthn_sessions',
      ]);
      const grantIndex = await pool.query<{ indexdef: string }>(
        `SELECT indexdef FROM pg_indexes
         WHERE schemaname = $1 AND indexname = 'localwebauthn_active_grant_user_idx'`,
        [NAMESPACE],
      );
      expect(grantIndex.rows[0].indexdef).toContain('COALESCE');

      // Idempotent, and the upgraded store works.
      await expect(migratePostgres(pool as unknown as PostgresPool, now)).resolves.toBeUndefined();
      const store = new PostgresLocalWebAuthnStore(pool as unknown as PostgresPool);
      expect(await store.claimDpopProof(new Uint8Array(32).fill(5), now + 60_000)).toBe(true);
      expect(await store.bumpRegistrationGeneration('user-1', now)).toBe(1);
      await expect(store.listCredentials('user-1')).resolves.toMatchObject([{ kind: null }]);
    } finally {
      await pool.end();
      const teardown = new pg.Pool({ connectionString: postgresUrl });
      await teardown.query(`DROP SCHEMA IF EXISTS ${NAMESPACE} CASCADE`);
      await teardown.end();
    }
  });
});

describe('a database from a newer build', () => {
  // Treating an unknown future version as "current" would run this code against
  // semantics it does not know — silently, because every table it knows is there.
  it('is refused rather than treated as current', () => {
    expect(() => localWebAuthnUpgradeStatements(LOCALWEBAUTHN_SCHEMA_VERSION + 1)).toThrow(
      /understands/u,
    );
    expect(() =>
      localWebAuthnUpgradeStatements(LOCALWEBAUTHN_SCHEMA_VERSION + 1, 'postgres'),
    ).toThrow(/understands/u);
    // The current version is still a no-op, not an error.
    expect(localWebAuthnUpgradeStatements(LOCALWEBAUTHN_SCHEMA_VERSION)).toEqual([]);
  });

  it('is refused by every runner', async () => {
    const database = new Database(':memory:');
    migrateSqlite(database, now);
    database
      .prepare('INSERT INTO localwebauthn_migrations(version, applied_at) VALUES (?, ?)')
      .run(LOCALWEBAUTHN_SCHEMA_VERSION + 5, now);
    expect(() => migrateSqlite(database, now)).toThrow(/understands/u);
    database.close();

    const d1 = await v1D1Database();
    await migrateD1(d1, now);
    await d1
      .prepare('INSERT INTO localwebauthn_migrations(version, applied_at) VALUES (?, ?)')
      .bind(LOCALWEBAUTHN_SCHEMA_VERSION + 5, now)
      .run();
    await expect(migrateD1(d1, now)).rejects.toThrow(/understands/u);
  });
});

describe('two D1 workers migrating at once', () => {
  // Both call migrateD1 against the same database. One wins; the loser's ALTERs
  // fail ("duplicate column name") and D1 rolls its batch back. That is a won
  // race, not corruption — but only if the loser then confirms the final version
  // rather than reporting success from stale state.
  it('converges from empty, with both callers succeeding', async () => {
    const database = await emptyD1();
    const [a, b] = await Promise.allSettled([migrateD1(database, now), migrateD1(database, now)]);
    expect([a.status, b.status]).toEqual(['fulfilled', 'fulfilled']);
    expect(await d1Version(database)).toBe(LOCALWEBAUTHN_SCHEMA_VERSION);
  });

  it('converges from a released v1 database, with both callers succeeding', async () => {
    const database = await v1D1Database();
    const [a, b] = await Promise.allSettled([migrateD1(database, now), migrateD1(database, now)]);
    expect([a.status, b.status]).toEqual(['fulfilled', 'fulfilled']);
    expect(await d1Version(database)).toBe(LOCALWEBAUTHN_SCHEMA_VERSION);

    // And the upgrade really happened rather than one caller giving up early.
    const store = new D1LocalWebAuthnStore(database);
    await expect(store.listCredentials('user-1')).resolves.toMatchObject([{ kind: null }]);
  });
});
