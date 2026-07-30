import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

import { migrateSqlite } from '@localwebauthn/server/sqlite';

export type DemoDatabase = Database.Database;
export type DemoRole = 'administrator' | 'client';

export type DemoClient = {
  id: string;
  email: string;
  displayName: string;
  role: DemoRole;
  active: boolean;
  createdAt: number;
};

type ClientRow = {
  id: string;
  email: string;
  display_name: string;
  role: DemoRole;
  active: number;
  created_at: number;
};

export function demoDatabasePath(): string {
  return process.env.DEMO_DATABASE_PATH ?? '.data/localwebauthn-demo.db';
}

export function openDemoDatabase(path = demoDatabasePath()): DemoDatabase {
  if (path !== ':memory:') {
    mkdirSync(dirname(path), { recursive: true });
  }
  const database = new Database(path);
  database.pragma('foreign_keys = ON');
  database.pragma('busy_timeout = 5000');
  if (path !== ':memory:') {
    database.pragma('journal_mode = WAL');
  }

  migrateSqlite(database);
  database.exec(`
    CREATE TABLE IF NOT EXISTS demo_clients (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL COLLATE NOCASE UNIQUE,
      display_name TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('administrator', 'client')),
      active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
      webauthn_user_handle BLOB NOT NULL UNIQUE
        CHECK (length(webauthn_user_handle) = 32),
      created_at INTEGER NOT NULL
    ) STRICT
  `);
  return database;
}

function clientFromRow(row: ClientRow): DemoClient {
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    role: row.role,
    active: row.active === 1,
    createdAt: row.created_at,
  };
}

export function clientById(database: DemoDatabase, id: string): DemoClient | null {
  const row = database
    .prepare(
      `SELECT id, email, display_name, role, active, created_at
       FROM demo_clients
       WHERE id = ?`,
    )
    .get(id) as ClientRow | undefined;
  return row ? clientFromRow(row) : null;
}

export function clientByEmail(database: DemoDatabase, email: string): DemoClient | null {
  const row = database
    .prepare(
      `SELECT id, email, display_name, role, active, created_at
       FROM demo_clients
       WHERE email = ? COLLATE NOCASE`,
    )
    .get(email) as ClientRow | undefined;
  return row ? clientFromRow(row) : null;
}

export function listClients(database: DemoDatabase): DemoClient[] {
  const rows = database
    .prepare(
      `SELECT id, email, display_name, role, active, created_at
       FROM demo_clients
       ORDER BY role, display_name COLLATE NOCASE`,
    )
    .all() as ClientRow[];
  return rows.map(clientFromRow);
}
