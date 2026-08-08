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
import { describe, expect, it } from 'vitest';

import { LOCALWEBAUTHN_SCHEMA_VERSION } from '../../packages/server/src/schema.js';
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
