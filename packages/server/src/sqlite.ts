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

import { ORPHANED_CREDENTIAL_GRACE_MS, SQL } from './queries.js';
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
import { LOCALWEBAUTHN_SCHEMA_SQL, LOCALWEBAUTHN_SCHEMA_VERSION } from './schema.js';

export type SqliteRunResult = {
  changes: number;
};

export type SqliteStatement = {
  run(...parameters: unknown[]): SqliteRunResult;
  get(...parameters: unknown[]): unknown;
  all(...parameters: unknown[]): unknown[];
};

export type SqliteDatabase = {
  exec(sql: string): unknown;
  prepare(sql: string): SqliteStatement;
  transaction<T>(operation: () => T): () => T;
};

/**
 * Create or update the `localwebauthn_*` tables. Idempotent — safe to call on
 * every start.
 */
export function migrateSqlite(database: SqliteDatabase, now = Date.now()): void {
  database.transaction(() => {
    database.exec(LOCALWEBAUTHN_SCHEMA_SQL);
    database.prepare(SQL.insertMigration).run(LOCALWEBAUTHN_SCHEMA_VERSION, now);
  })();
}

/**
 * {@link LocalWebAuthnStore} backed by better-sqlite3 (or any driver with the
 * same synchronous `prepare`/`transaction` shape).
 *
 * Every multi-statement operation runs inside a real SQLite transaction, so
 * partial writes cannot be observed or left behind.
 */
export class SqliteLocalWebAuthnStore implements LocalWebAuthnStore {
  readonly #database;

  constructor(database: SqliteDatabase) {
    this.#database = database;
  }

  async replaceEnrollmentGrant(record: EnrollmentGrantRecord): Promise<string[]> {
    return this.#database.transaction(() => {
      const revoked = this.#database
        .prepare(SQL.revokePendingGrants)
        .all(record.createdAt, record.userId) as { id: string }[];
      this.#database
        .prepare(SQL.insertEnrollmentGrant)
        .run(
          record.id,
          record.userId,
          record.tokenHash,
          record.expiresAt,
          record.approvedByUserId,
          record.createdAt,
        );
      return revoked.map((row) => row.id);
    })();
  }

  async exchangeEnrollment(
    tokenHash: Uint8Array,
    sessionHash: Uint8Array,
    sessionExpiresAt: number,
    now: number,
  ): Promise<EnrollmentSession | null> {
    const row = this.#database
      .prepare(SQL.exchangeEnrollment)
      .get(now, sessionHash, sessionExpiresAt, tokenHash, now) as EnrollmentSessionRow | undefined;
    return row ? enrollmentSessionFromRow(row) : null;
  }

  async resolveEnrollmentSession(
    sessionHash: Uint8Array,
    now: number,
  ): Promise<EnrollmentSession | null> {
    const row = this.#database.prepare(SQL.selectEnrollmentSession).get(sessionHash, now) as
      EnrollmentSessionRow | undefined;
    return row ? enrollmentSessionFromRow(row) : null;
  }

  async createChallenge(record: ChallengeRecord): Promise<boolean> {
    return (
      this.#database
        .prepare(SQL.insertChallenge)
        .run(
          record.idHash,
          record.kind,
          record.challenge,
          record.userId,
          record.grantId,
          record.authorizationSessionHash,
          record.expiresAt,
          record.createdAt,
        ).changes === 1
    );
  }

  async consumeChallenge(
    idHash: Uint8Array,
    kind: ChallengeKind,
    now: number,
  ): Promise<ConsumedChallenge | null> {
    const row = this.#database.prepare(SQL.consumeChallenge).get(now, idHash, kind, now) as
      ChallengeRow | undefined;
    return row ? challengeFromRow(row) : null;
  }

  async listCredentials(userId: string, includeRevoked = false): Promise<Credential[]> {
    const rows = this.#database
      .prepare(SQL.selectCredentialsForUser)
      .all(userId, includeRevoked ? 1 : 0) as CredentialRow[];
    return rows.map(credentialFromRow);
  }

  async getCredential(credentialId: string): Promise<Credential | null> {
    const row = this.#database.prepare(SQL.selectCredentialById).get(credentialId) as
      CredentialRow | undefined;
    return row ? credentialFromRow(row) : null;
  }

  async completeRegistration(input: CompleteRegistrationInput): Promise<boolean> {
    try {
      return this.#database.transaction(() => {
        if (!this.#registrationIsAuthorized(input)) {
          return false;
        }

        const credential = input.credential;
        this.#database
          .prepare(SQL.insertCredential)
          .run(
            credential.id,
            credential.userId,
            credential.publicKey,
            credential.counter,
            JSON.stringify(credential.transports),
            credential.deviceType,
            credential.backedUp ? 1 : 0,
            credential.label,
            credential.createdAt,
          );

        if (input.challenge.grantId) {
          const completion = this.#database
            .prepare(SQL.completeEnrollmentGrant)
            .run(input.now, input.challenge.grantId, input.enrollmentSessionHash, input.now);
          if (completion.changes !== 1) {
            // Roll the whole registration back: the grant moved under us.
            throw new Error('Enrollment grant changed during registration.');
          }
        }

        this.#insertSession(input.session);
        return true;
      })();
    } catch {
      return false;
    }
  }

  async completeAuthentication(input: CompleteAuthenticationInput): Promise<boolean> {
    try {
      return this.#database.transaction(() => {
        const advanced = this.#database
          .prepare(SQL.advanceCredentialCounter)
          .run(input.newCounter, input.now, input.credentialId, input.previousCounter);
        if (advanced.changes !== 1) {
          return false;
        }
        this.#insertSession(input.session);
        return true;
      })();
    } catch {
      return false;
    }
  }

  async resolveSession(
    idHash: Uint8Array,
    now: number,
    idleExpiresBefore: number,
  ): Promise<SessionIdentity | null> {
    const row = this.#database.prepare(SQL.selectSession).get(idHash, now, idleExpiresBefore) as
      SessionRow | undefined;
    return row ? sessionFromRow(row) : null;
  }

  async touchSession(idHash: Uint8Array, now: number): Promise<boolean> {
    return this.#database.prepare(SQL.touchSession).run(now, idHash, now).changes === 1;
  }

  async revokeSession(idHash: Uint8Array, now: number): Promise<boolean> {
    return this.#database.prepare(SQL.revokeSession).run(now, idHash).changes === 1;
  }

  async revokeCredential(userId: string, credentialId: string, now: number): Promise<boolean> {
    return this.#database.transaction(() => {
      const revoked = this.#database.prepare(SQL.revokeCredential).run(now, credentialId, userId);
      if (revoked.changes !== 1) {
        return false;
      }
      this.#database.prepare(SQL.revokeSessionsForCredential).run(now, credentialId);
      return true;
    })();
  }

  async revokeUserAuthentication(userId: string, now: number): Promise<void> {
    this.#database.transaction(() => {
      this.#database.prepare(SQL.revokeUserCredentials).run(now, userId);
      this.#database.prepare(SQL.revokeUserSessions).run(now, userId);
      this.#database.prepare(SQL.revokeUserGrants).run(now, userId);
      this.#database.prepare(SQL.consumeUserChallenges).run(now, userId);
    })();
  }

  async cleanup(now: number): Promise<CleanupResult> {
    return this.#database.transaction(() => {
      const sessions = this.#database.prepare(SQL.deleteExpiredSessions).run(now).changes;
      const orphanedCredentials = this.#database
        .prepare(SQL.deleteOrphanedCredentials)
        .run(now - ORPHANED_CREDENTIAL_GRACE_MS).changes;
      const enrollmentGrants = this.#database.prepare(SQL.deleteFinishedGrants).run(now).changes;
      const challenges = this.#database.prepare(SQL.deleteFinishedChallenges).run(now).changes;
      return { enrollmentGrants, challenges, sessions, orphanedCredentials };
    })();
  }

  /** Re-check the authorizing grant or session at commit time. */
  #registrationIsAuthorized(input: CompleteRegistrationInput): boolean {
    if (input.challenge.grantId && input.enrollmentSessionHash) {
      return Boolean(
        this.#database
          .prepare(SQL.authorizeRegistrationByGrant)
          .get(
            input.challenge.grantId,
            input.credential.userId,
            input.enrollmentSessionHash,
            input.now,
          ),
      );
    }

    if (input.challenge.authorizationSessionHash && input.authenticatedSessionHash) {
      return Boolean(
        this.#database
          .prepare(SQL.authorizeRegistrationBySession)
          .get(input.authenticatedSessionHash, input.credential.userId, input.now),
      );
    }
    return false;
  }

  #insertSession(session: NewSession): void {
    this.#database
      .prepare(SQL.insertSession)
      .run(
        session.idHash,
        session.userId,
        session.credentialId,
        session.authenticatedAt,
        session.expiresAt,
        session.lastSeenAt,
      );
  }
}
