import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

import { createUserHandle } from '@localwebauthn/server';
import { migrateSqlite } from '@localwebauthn/server/sqlite';

export type StarterDatabase = Database.Database;

export type StarterUser = {
  id: string;
  email: string;
  displayName: string;
  active: boolean;
  webAuthnUserHandle: Uint8Array;
};

export function openDatabase(path = process.env.STARTER_DATABASE_PATH ?? '.data/starter.db') {
  if (path !== ':memory:') {
    mkdirSync(dirname(path), { recursive: true });
  }
  const database = new Database(path);
  database.pragma('foreign_keys = ON');
  migrateSqlite(database);
  database.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL COLLATE NOCASE UNIQUE,
      display_name TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      webauthn_user_handle BLOB NOT NULL UNIQUE
        CHECK (length(webauthn_user_handle) = 32),
      pending_enrollment INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    ) STRICT
  `);
  return database;
}

export function getUser(database: StarterDatabase, id: string): StarterUser | null {
  const row = database
    .prepare(
      `SELECT id, email, display_name, active, webauthn_user_handle
       FROM users WHERE id = ?`,
    )
    .get(id) as
    | {
        id: string;
        email: string;
        display_name: string;
        active: number;
        webauthn_user_handle: Buffer;
      }
    | undefined;
  if (!row) {
    return null;
  }
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    active: row.active === 1,
    webAuthnUserHandle: new Uint8Array(row.webauthn_user_handle),
  };
}

export function getUserByEmail(database: StarterDatabase, email: string): StarterUser | null {
  const row = database.prepare(`SELECT id FROM users WHERE email = ?`).get(email) as
    { id: string } | undefined;
  return row ? getUser(database, row.id) : null;
}

export function ensureUser(
  database: StarterDatabase,
  input: { id: string; email: string; displayName: string },
): StarterUser {
  const existing = getUser(database, input.id);
  if (existing) {
    return existing;
  }
  database
    .prepare(
      `INSERT INTO users(id, email, display_name, webauthn_user_handle, pending_enrollment, created_at)
       VALUES (?, ?, ?, ?, 1, ?)`,
    )
    .run(input.id, input.email, input.displayName, createUserHandle(), Date.now());
  const created = getUser(database, input.id);
  if (!created) {
    throw new Error('User insert failed.');
  }
  return created;
}

export function setPendingEnrollment(database: StarterDatabase, userId: string, pending: boolean) {
  database
    .prepare(`UPDATE users SET pending_enrollment = ? WHERE id = ?`)
    .run(pending ? 1 : 0, userId);
}

export function hasPendingEnrollment(database: StarterDatabase, userId: string): boolean {
  const row = database.prepare(`SELECT pending_enrollment FROM users WHERE id = ?`).get(userId) as
    { pending_enrollment: number } | undefined;
  return row?.pending_enrollment === 1;
}
