import type {
  ChallengeKind,
  ChallengeRecord,
  CleanupResult,
  CompleteAuthenticationInput,
  CompleteRegistrationInput,
  ConsumedChallenge,
  Credential,
  EnrollmentGrantRecord,
  EnrollmentSession,
  LocalWebAuthnStore,
  NewSession,
  SessionIdentity,
} from './types.js';

import { ORPHANED_CREDENTIAL_GRACE_MS, SQL, toPositionalPlaceholders } from './queries.js';
import {
  type ChallengeRow,
  challengeFromRow,
  type CredentialRow,
  credentialFromRow,
  type EnrollmentSessionRow,
  enrollmentSessionFromRow,
  type SessionRow,
  sessionFromRow,
} from './rows.js';
import { LOCALWEBAUTHN_POSTGRES_SCHEMA_SQL, LOCALWEBAUTHN_SCHEMA_VERSION } from './schema.js';

/** The shared statements with `?` rewritten to PostgreSQL's `$1`, `$2`, … form. */
const PG: { [Name in keyof typeof SQL]: string } = Object.fromEntries(
  Object.entries(SQL).map(([name, sql]) => [name, toPositionalPlaceholders(sql)]),
) as { [Name in keyof typeof SQL]: string };

export type PostgresQueryResult<Row> = {
  rows: Row[];
  rowCount: number | null;
};

/** The subset of a node-postgres client this adapter uses. */
export type PostgresQueryable = {
  query<Row = Record<string, unknown>>(
    sql: string,
    parameters?: unknown[],
  ): Promise<PostgresQueryResult<Row>>;
};

export type PostgresPoolClient = PostgresQueryable & {
  release(): void;
};

/**
 * A `pg.Pool`, or anything with the same shape.
 *
 * A pool rather than a single client is required: transactions need a
 * connection to themselves, and issuing `BEGIN` on a connection shared between
 * concurrent requests would interleave unrelated statements into the same
 * transaction.
 */
export type PostgresPool = PostgresQueryable & {
  connect(): Promise<PostgresPoolClient>;
};

/** Thrown inside a transaction to force a rollback and report `false`. */
class Rollback extends Error {}

/**
 * Create or update the `localwebauthn_*` tables. Idempotent — safe to call on
 * every start.
 *
 * ```ts
 * import { Pool } from 'pg';
 * import { migratePostgres, PostgresLocalWebAuthnStore } from '@localwebauthn/server/postgres';
 *
 * const pool = new Pool({ connectionString: process.env.DATABASE_URL });
 * await migratePostgres(pool);
 * const store = new PostgresLocalWebAuthnStore(pool);
 * ```
 */
export async function migratePostgres(pool: PostgresPool, now = Date.now()): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(LOCALWEBAUTHN_POSTGRES_SCHEMA_SQL);
    await client.query(PG.insertMigration, [LOCALWEBAUTHN_SCHEMA_VERSION, now]);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

/**
 * {@link LocalWebAuthnStore} backed by PostgreSQL.
 *
 * Like the SQLite adapter and unlike D1, every multi-statement operation runs
 * inside a real transaction, so partial writes cannot be observed or left
 * behind.
 */
export class PostgresLocalWebAuthnStore implements LocalWebAuthnStore {
  readonly #pool;

  constructor(pool: PostgresPool) {
    this.#pool = pool;
  }

  async replaceEnrollmentGrant(record: EnrollmentGrantRecord): Promise<string[]> {
    return this.#transaction(async (tx) => {
      const revoked = await tx.query<{ id: string }>(PG.revokePendingGrants, [
        record.createdAt,
        record.userId,
      ]);
      await tx.query(PG.insertEnrollmentGrant, [
        record.id,
        record.userId,
        record.tokenHash,
        record.expiresAt,
        record.approvedByUserId,
        record.createdAt,
      ]);
      return revoked.rows.map((row) => row.id);
    });
  }

  async exchangeEnrollment(
    tokenHash: Uint8Array,
    sessionHash: Uint8Array,
    sessionExpiresAt: number,
    now: number,
  ): Promise<EnrollmentSession | null> {
    const result = await this.#pool.query<EnrollmentSessionRow>(PG.exchangeEnrollment, [
      now,
      sessionHash,
      sessionExpiresAt,
      tokenHash,
      now,
    ]);
    const row = result.rows.at(0);
    return row ? enrollmentSessionFromRow(row) : null;
  }

  async resolveEnrollmentSession(
    sessionHash: Uint8Array,
    now: number,
  ): Promise<EnrollmentSession | null> {
    const result = await this.#pool.query<EnrollmentSessionRow>(PG.selectEnrollmentSession, [
      sessionHash,
      now,
    ]);
    const row = result.rows.at(0);
    return row ? enrollmentSessionFromRow(row) : null;
  }

  async createChallenge(record: ChallengeRecord): Promise<boolean> {
    const result = await this.#pool.query(PG.insertChallenge, [
      record.idHash,
      record.kind,
      record.challenge,
      record.userId,
      record.grantId,
      record.authorizationSessionHash,
      record.expiresAt,
      record.createdAt,
    ]);
    return result.rowCount === 1;
  }

  async consumeChallenge(
    idHash: Uint8Array,
    kind: ChallengeKind,
    now: number,
  ): Promise<ConsumedChallenge | null> {
    const result = await this.#pool.query<ChallengeRow>(PG.consumeChallenge, [
      now,
      idHash,
      kind,
      now,
    ]);
    const row = result.rows.at(0);
    return row ? challengeFromRow(row) : null;
  }

  async listCredentials(userId: string, includeRevoked = false): Promise<Credential[]> {
    const result = await this.#pool.query<CredentialRow>(PG.selectCredentialsForUser, [
      userId,
      includeRevoked ? 1 : 0,
    ]);
    return result.rows.map(credentialFromRow);
  }

  async getCredential(credentialId: string): Promise<Credential | null> {
    const result = await this.#pool.query<CredentialRow>(PG.selectCredentialById, [credentialId]);
    const row = result.rows.at(0);
    return row ? credentialFromRow(row) : null;
  }

  async completeRegistration(input: CompleteRegistrationInput): Promise<boolean> {
    try {
      return await this.#transaction(async (tx) => {
        if (!(await this.#registrationIsAuthorized(tx, input))) {
          throw new Rollback();
        }

        const credential = input.credential;
        await tx.query(PG.insertCredential, [
          credential.id,
          credential.userId,
          credential.publicKey,
          credential.counter,
          JSON.stringify(credential.transports),
          credential.deviceType,
          credential.backedUp,
          credential.label,
          credential.createdAt,
        ]);

        if (input.challenge.grantId) {
          const completion = await tx.query(PG.completeEnrollmentGrant, [
            input.now,
            input.challenge.grantId,
            input.enrollmentSessionHash,
            input.now,
          ]);
          if (completion.rowCount !== 1) {
            // Roll the whole registration back: the grant moved under us.
            throw new Rollback();
          }
        }

        await this.#insertSession(tx, input.session);
        return true;
      });
    } catch {
      return false;
    }
  }

  async completeAuthentication(input: CompleteAuthenticationInput): Promise<boolean> {
    try {
      return await this.#transaction(async (tx) => {
        const advanced = await tx.query(PG.advanceCredentialCounter, [
          input.newCounter,
          input.now,
          input.credentialId,
          input.previousCounter,
        ]);
        if (advanced.rowCount !== 1) {
          throw new Rollback();
        }
        await this.#insertSession(tx, input.session);
        return true;
      });
    } catch {
      return false;
    }
  }

  async resolveSession(
    idHash: Uint8Array,
    now: number,
    idleExpiresBefore: number,
  ): Promise<SessionIdentity | null> {
    const result = await this.#pool.query<SessionRow>(PG.selectSession, [
      idHash,
      now,
      idleExpiresBefore,
    ]);
    const row = result.rows.at(0);
    return row ? sessionFromRow(row) : null;
  }

  async touchSession(idHash: Uint8Array, now: number): Promise<boolean> {
    const result = await this.#pool.query(PG.touchSession, [now, idHash, now]);
    return result.rowCount === 1;
  }

  async revokeSession(idHash: Uint8Array, now: number): Promise<boolean> {
    const result = await this.#pool.query(PG.revokeSession, [now, idHash]);
    return result.rowCount === 1;
  }

  async revokeCredential(userId: string, credentialId: string, now: number): Promise<boolean> {
    return this.#transaction(async (tx) => {
      const revoked = await tx.query(PG.revokeCredential, [now, credentialId, userId]);
      if (revoked.rowCount !== 1) {
        return false;
      }
      await tx.query(PG.revokeSessionsForCredential, [now, credentialId]);
      return true;
    });
  }

  async revokeUserAuthentication(userId: string, now: number): Promise<void> {
    await this.#transaction(async (tx) => {
      await tx.query(PG.revokeUserCredentials, [now, userId]);
      await tx.query(PG.revokeUserSessions, [now, userId]);
      await tx.query(PG.revokeUserGrants, [now, userId]);
      await tx.query(PG.consumeUserChallenges, [now, userId]);
    });
  }

  async cleanup(now: number): Promise<CleanupResult> {
    return this.#transaction(async (tx) => {
      const sessions = await tx.query(PG.deleteExpiredSessions, [now]);
      const orphanedCredentials = await tx.query(PG.deleteOrphanedCredentials, [
        now - ORPHANED_CREDENTIAL_GRACE_MS,
      ]);
      const enrollmentGrants = await tx.query(PG.deleteFinishedGrants, [now]);
      const challenges = await tx.query(PG.deleteFinishedChallenges, [now]);
      return {
        sessions: sessions.rowCount ?? 0,
        orphanedCredentials: orphanedCredentials.rowCount ?? 0,
        enrollmentGrants: enrollmentGrants.rowCount ?? 0,
        challenges: challenges.rowCount ?? 0,
      };
    });
  }

  /** Re-check the authorizing grant or session at commit time. */
  async #registrationIsAuthorized(
    tx: PostgresQueryable,
    input: CompleteRegistrationInput,
  ): Promise<boolean> {
    if (input.challenge.grantId && input.enrollmentSessionHash) {
      const result = await tx.query(PG.authorizeRegistrationByGrant, [
        input.challenge.grantId,
        input.credential.userId,
        input.enrollmentSessionHash,
        input.now,
      ]);
      return result.rows.length > 0;
    }

    if (input.challenge.authorizationSessionHash && input.authenticatedSessionHash) {
      const result = await tx.query(PG.authorizeRegistrationBySession, [
        input.authenticatedSessionHash,
        input.credential.userId,
        input.now,
      ]);
      return result.rows.length > 0;
    }
    return false;
  }

  async #insertSession(tx: PostgresQueryable, session: NewSession): Promise<void> {
    await tx.query(PG.insertSession, [
      session.idHash,
      session.userId,
      session.credentialId,
      session.authenticatedAt,
      session.expiresAt,
      session.lastSeenAt,
    ]);
  }

  async #transaction<T>(operation: (tx: PostgresQueryable) => Promise<T>): Promise<T> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const result = await operation(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }
}
