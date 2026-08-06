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
  // Self-serve signup proofing state (host-owned; see channels-core signup.ts).
  // enrollment_token is the post-completion claim escrow: raw by necessity —
  // any proved channel may claim it until the signup expires. It is single-use
  // at the LocalWebAuthn layer and this row is bounded by expires_at.
  database.exec(`
    CREATE TABLE IF NOT EXISTS demo_signups (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL COLLATE NOCASE,
      phone TEXT NOT NULL,
      display_name TEXT NOT NULL,
      otp_email_hash BLOB NOT NULL,
      otp_phone_hash BLOB NOT NULL,
      email_proved_at INTEGER,
      phone_proved_at INTEGER,
      consumed_at INTEGER,
      client_id TEXT,
      enrollment_token TEXT,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    ) STRICT
  `);
  return database;
}

export type DemoSignup = {
  id: string;
  email: string;
  phone: string;
  displayName: string;
  otpEmailHash: Uint8Array;
  otpPhoneHash: Uint8Array;
  emailProvedAt: number | null;
  phoneProvedAt: number | null;
  consumedAt: number | null;
  clientId: string | null;
  enrollmentToken: string | null;
  expiresAt: number;
};

type SignupRow = {
  id: string;
  email: string;
  phone: string;
  display_name: string;
  otp_email_hash: Buffer;
  otp_phone_hash: Buffer;
  email_proved_at: number | null;
  phone_proved_at: number | null;
  consumed_at: number | null;
  client_id: string | null;
  enrollment_token: string | null;
  expires_at: number;
};

export function insertSignup(
  database: DemoDatabase,
  signup: Omit<
    DemoSignup,
    'emailProvedAt' | 'phoneProvedAt' | 'consumedAt' | 'clientId' | 'enrollmentToken'
  >,
): void {
  database
    .prepare(
      `INSERT INTO demo_signups(
         id, email, phone, display_name, otp_email_hash, otp_phone_hash,
         expires_at, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      signup.id,
      signup.email,
      signup.phone,
      signup.displayName,
      signup.otpEmailHash,
      signup.otpPhoneHash,
      signup.expiresAt,
      Date.now(),
    );
}

export function signupById(database: DemoDatabase, id: string): DemoSignup | null {
  const row = database.prepare(`SELECT * FROM demo_signups WHERE id = ?`).get(id) as
    SignupRow | undefined;
  if (!row) {
    return null;
  }
  return {
    id: row.id,
    email: row.email,
    phone: row.phone,
    displayName: row.display_name,
    otpEmailHash: new Uint8Array(row.otp_email_hash),
    otpPhoneHash: new Uint8Array(row.otp_phone_hash),
    emailProvedAt: row.email_proved_at,
    phoneProvedAt: row.phone_proved_at,
    consumedAt: row.consumed_at,
    clientId: row.client_id,
    enrollmentToken: row.enrollment_token,
    expiresAt: row.expires_at,
  };
}

export function markSignupProved(
  database: DemoDatabase,
  id: string,
  channel: 'email' | 'phone',
  now: number,
): void {
  const column = channel === 'email' ? 'email_proved_at' : 'phone_proved_at';
  database
    .prepare(`UPDATE demo_signups SET ${column} = ? WHERE id = ? AND ${column} IS NULL`)
    .run(now, id);
}

export function completeSignup(
  database: DemoDatabase,
  id: string,
  input: { clientId: string; enrollmentToken: string; now: number },
): void {
  database
    .prepare(
      `UPDATE demo_signups
       SET consumed_at = ?, client_id = ?, enrollment_token = ?
       WHERE id = ? AND consumed_at IS NULL`,
    )
    .run(input.now, input.clientId, input.enrollmentToken, id);
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
