import type {
  ChallengeKind,
  ChallengeRecord,
  CleanupResult,
  CompleteAuthenticationInput,
  CompleteRegistrationInput,
  ConsumedChallenge,
  Credential,
  EnrollmentGrantRecord,
  EnrollmentGrantRejection,
  EnrollmentSession,
  LocalWebAuthnDpopStore,
  LocalWebAuthnStore,
  NewSession,
  RevokeCredentialResult,
  RevokedSession,
  SessionIdentity,
} from './types.js';

import { SQL } from './queries.js';
import {
  type ChallengeRow,
  challengeFromRow,
  type CredentialRow,
  credentialFromRow,
  type EnrollmentGrantStateRow,
  enrollmentGrantStateFromRow,
  type EnrollmentSessionRow,
  enrollmentSessionFromRow,
  type SessionRow,
  sessionFromRow,
} from './rows.js';
import {
  LOCALWEBAUTHN_SCHEMA_VERSION,
  localWebAuthnMigrationsTableStatement,
  localWebAuthnUpgradeStatements,
} from './schema.js';

export type SqliteRunResult = {
  changes: number;
};

export type SqliteStatement = {
  run(...parameters: unknown[]): SqliteRunResult;
  get(...parameters: unknown[]): unknown;
  all(...parameters: unknown[]): unknown[];
};

/**
 * better-sqlite3's transaction function: callable (BEGIN DEFERRED) with an
 * `immediate()` variant (BEGIN IMMEDIATE). The adapter always uses
 * `immediate()`: a deferred transaction that reads before writing cannot be
 * retried by `busy_timeout` under WAL once another connection has written
 * (`SQLITE_BUSY_SNAPSHOT`), and every transaction here writes.
 */
export type SqliteTransaction<T> = {
  (): T;
  immediate(): T;
};

export type SqliteDatabase = {
  exec(sql: string): unknown;
  prepare(sql: string): SqliteStatement;
  transaction<T>(operation: () => T): SqliteTransaction<T>;
};

/**
 * Create or update the `localwebauthn_*` tables. Idempotent — safe to call on
 * every start.
 *
 * Enables `PRAGMA foreign_keys = ON` on this connection. SQLite does not enforce
 * foreign keys unless that pragma is set; keep using the same connection for
 * the store so the schema constraints remain active.
 */
/** Thrown inside a transaction to roll it back and report `false`. */
class Rollback extends Error {}

export function migrateSqlite(database: SqliteDatabase, now = Date.now()): void {
  database.exec('PRAGMA foreign_keys = ON');
  database
    .transaction(() => {
      // The version table has to exist before its own version can be read.
      database.exec(localWebAuthnMigrationsTableStatement('sqlite'));
      const stored = database.prepare(SQL.selectSchemaVersion).get() as
        { version: number | null } | undefined;
      const from = stored?.version ?? 0;
      for (const statement of localWebAuthnUpgradeStatements(from, 'sqlite')) {
        database.exec(statement);
      }
      database.prepare(SQL.insertMigration).run(LOCALWEBAUTHN_SCHEMA_VERSION, now);
    })
    .immediate();
}

/**
 * {@link LocalWebAuthnStore} backed by better-sqlite3 (or any driver with the
 * same synchronous `prepare`/`transaction` shape).
 *
 * Every multi-statement operation runs inside a real SQLite transaction, so
 * partial writes cannot be observed or left behind. The constructor enables
 * foreign-key enforcement on the given connection.
 */
export class SqliteLocalWebAuthnStore implements LocalWebAuthnStore, LocalWebAuthnDpopStore {
  readonly #database;

  constructor(database: SqliteDatabase) {
    this.#database = database;
    database.exec('PRAGMA foreign_keys = ON');
  }

  async replaceEnrollmentGrant(record: EnrollmentGrantRecord): Promise<string[]> {
    return this.#database
      .transaction(() => {
        // Kind-scoped: replacing a person's pending link must not cancel a
        // pending deployment-key grant, or vice versa.
        const revoked = this.#database
          .prepare(SQL.revokePendingGrants)
          .all(record.createdAt, record.userId, record.credentialKind) as { id: string }[];
        this.#database
          .prepare(SQL.insertEnrollmentGrant)
          .run(
            record.id,
            record.userId,
            record.tokenHash,
            record.expiresAt,
            record.approvedByUserId,
            record.credentialKind,
            record.createdAt,
          );
        return revoked.map((row) => row.id);
      })
      .immediate();
  }

  async revokePendingEnrollmentGrants(
    userId: string,
    now: number,
    credentialKind: string | null,
  ): Promise<string[]> {
    const rows = this.#database
      .prepare(SQL.revokePendingGrants)
      .all(now, userId, credentialKind) as { id: string }[];
    return rows.map((row) => row.id);
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

  async enrollmentGrantState(
    tokenHash: Uint8Array,
    now: number,
  ): Promise<EnrollmentGrantRejection> {
    const row = this.#database.prepare(SQL.selectEnrollmentGrantState).get(tokenHash) as
      EnrollmentGrantStateRow | undefined;
    return row ? enrollmentGrantStateFromRow(row, now) : { state: 'unknown', userId: null };
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
          record.credentialKind,
          record.allowedCredentialKinds === null
            ? null
            : JSON.stringify(record.allowedCredentialKinds),
          record.registrationGeneration,
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

  async credentialAncestry(userId: string, credentialId: string): Promise<Credential[]> {
    const rows = this.#database
      .prepare(SQL.selectCredentialAncestry)
      .all(credentialId, userId) as CredentialRow[];
    return rows.map(credentialFromRow);
  }

  async credentialDescendants(userId: string, credentialId: string): Promise<Credential[]> {
    const rows = this.#database
      .prepare(SQL.selectCredentialDescendants)
      .all(credentialId, userId) as CredentialRow[];
    return rows.map(credentialFromRow);
  }

  async completeRegistration(input: CompleteRegistrationInput): Promise<boolean> {
    try {
      return this.#database
        .transaction(() => {
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
              credential.kind,
              credential.createdVia,
              credential.parentCredentialId,
              credential.grantId,
              credential.approvedByUserId,
              credential.createdAt,
            );

          if (input.challenge.grantId) {
            const completion = this.#database
              .prepare(SQL.completeEnrollmentGrant)
              .run(input.now, input.challenge.grantId, input.enrollmentSessionHash, input.now);
            if (completion.changes !== 1) {
              // Roll the whole registration back: the grant moved under us.
              throw new Rollback();
            }
          }

          this.#insertSession(input.session);
          return true;
        })
        .immediate();
    } catch (error) {
      // Only the deliberate rollback reports `false` (authorization lost).
      // Anything else is a real storage fault the host must see — swallowing
      // it here told enrollees their valid link had expired. (#6)
      if (error instanceof Rollback) {
        return false;
      }
      throw error;
    }
  }

  async completeAuthentication(input: CompleteAuthenticationInput): Promise<boolean> {
    // `false` means the counter compare-and-swap was lost; storage faults
    // propagate rather than masquerading as a failed authentication. (#6)
    return this.#database
      .transaction(() => {
        const advanced = this.#database
          .prepare(SQL.advanceCredentialCounter)
          .run(
            input.newCounter,
            input.now,
            input.credentialId,
            input.previousCounter,
            input.newCounter,
            input.newCounter,
          );
        if (advanced.changes !== 1) {
          return false;
        }
        this.#insertSession(input.session);
        return true;
      })
      .immediate();
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

  async revokeSession(idHash: Uint8Array, now: number): Promise<RevokedSession | null> {
    const row = this.#database.prepare(SQL.revokeSession).get(now, idHash) as
      { user_id: string; credential_id: string } | undefined;
    return row ? { userId: row.user_id, credentialId: row.credential_id } : null;
  }

  async revokeUserSessions(
    userId: string,
    now: number,
    idleExpiresBefore: number,
    exceptSessionHash?: Uint8Array,
  ): Promise<number> {
    if (exceptSessionHash) {
      return this.#database
        .prepare(SQL.revokeLiveUserSessionsExcept)
        .run(now, userId, now, idleExpiresBefore, exceptSessionHash).changes;
    }
    return this.#database
      .prepare(SQL.revokeLiveUserSessions)
      .run(now, userId, now, idleExpiresBefore).changes;
  }

  async revokeLiveCredentialSessions(
    credentialId: string,
    now: number,
    idleExpiresBefore: number,
    exceptSessionHash?: Uint8Array,
  ): Promise<number> {
    return exceptSessionHash
      ? this.#database
          .prepare(SQL.revokeLiveCredentialSessionsExcept)
          .run(now, credentialId, now, idleExpiresBefore, exceptSessionHash).changes
      : this.#database
          .prepare(SQL.revokeLiveCredentialSessions)
          .run(now, credentialId, now, idleExpiresBefore).changes;
  }

  async revokeCredential(
    userId: string,
    credentialId: string,
    now: number,
    options: { allowLastCredential?: boolean } = {},
  ): Promise<RevokeCredentialResult> {
    return this.#database
      .transaction(() => {
        const allowLast = options.allowLastCredential ? 1 : 0;
        const revoked = this.#database
          .prepare(SQL.revokeCredential)
          .run(now, credentialId, userId, allowLast, userId, credentialId);
        if (revoked.changes === 1) {
          this.#database.prepare(SQL.revokeSessionsForCredential).run(now, credentialId);
          return 'revoked';
        }
        if (
          !options.allowLastCredential &&
          this.#database
            .prepare(SQL.isLastActiveCredential)
            .get(credentialId, userId, userId, credentialId)
        ) {
          return 'last_credential';
        }
        return 'not_found';
      })
      .immediate();
  }

  async revokeUserAuthentication(userId: string, now: number): Promise<void> {
    this.#database
      .transaction(() => {
        this.#database.prepare(SQL.revokeUserCredentials).run(now, userId);
        this.#database.prepare(SQL.revokeUserSessions).run(now, userId);
        this.#database.prepare(SQL.revokeUserGrants).run(now, userId);
        this.#database.prepare(SQL.consumeUserChallenges).run(now, userId);
      })
      .immediate();
  }

  async claimDpopProof(jtiHash: Uint8Array, expiresAt: number): Promise<boolean> {
    return this.#database.prepare(SQL.claimDpopProof).run(jtiHash, expiresAt).changes === 1;
  }

  async claimDpopNonce(slot: number, candidate: string, expiresAt: number): Promise<string> {
    return this.#database
      .transaction(() => {
        this.#database.prepare(SQL.insertDpopNonce).run(slot, candidate, expiresAt);
        // Read back rather than returning `candidate`: on a lost insert the stored
        // value is another server's, and both must agree.
        const row = this.#database.prepare(SQL.selectDpopNonce).get(slot) as
          { nonce: string } | undefined;
        return row?.nonce ?? candidate;
      })
      .immediate();
  }

  async dpopNonces(currentSlot: number, previousSlot: number): Promise<string[]> {
    const rows = this.#database.prepare(SQL.selectDpopNonces).all(currentSlot, previousSlot) as {
      nonce: string;
    }[];
    return rows.map((row) => row.nonce);
  }

  async cleanup(now: number): Promise<CleanupResult> {
    return this.#database
      .transaction(() => {
        const sessions = this.#database.prepare(SQL.deleteExpiredSessions).run(now).changes;
        const enrollmentGrants = this.#database.prepare(SQL.deleteFinishedGrants).run(now).changes;
        const challenges = this.#database.prepare(SQL.deleteFinishedChallenges).run(now).changes;
        const dpopProofs = this.#database.prepare(SQL.deleteExpiredDpopProofs).run(now).changes;
        const dpopNonces = this.#database.prepare(SQL.deleteExpiredDpopNonces).run(now).changes;
        return { enrollmentGrants, challenges, sessions, dpopProofs, dpopNonces };
      })
      .immediate();
  }

  /** Re-check the authorizing grant or session at commit time. */
  #registrationIsAuthorized(input: CompleteRegistrationInput): boolean {
    // The registration fence, checked inside the committing transaction. The
    // challenge recorded the generation it was issued under; if a revocation has
    // advanced it since, this registration was authorized by a world that no
    // longer exists and must not commit. SQLite serializes writers, so reading it
    // here (in an `immediate` transaction) is enough — PostgreSQL additionally
    // locks the row, see its `#registrationIsAuthorized`.
    if (!this.#fenceHolds(input)) {
      return false;
    }

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

  /** Whether the challenge's recorded generation is still the current one. */
  #fenceHolds(input: CompleteRegistrationInput): boolean {
    const expected = input.challenge.registrationGeneration;
    if (expected === null) {
      // A challenge issued before this column existed. Nothing to compare.
      return true;
    }
    const row = this.#database.prepare(SQL.selectRegistrationFence).get(input.credential.userId) as
      { generation: number } | undefined;
    return (row?.generation ?? 0) === expected;
  }

  async registrationGeneration(userId: string, now: number): Promise<number> {
    this.#database.prepare(SQL.ensureRegistrationFence).run(userId, now);
    const row = this.#database.prepare(SQL.selectRegistrationFence).get(userId) as
      { generation: number } | undefined;
    return row?.generation ?? 0;
  }

  async bumpRegistrationGeneration(userId: string, now: number): Promise<number> {
    const row = this.#database.prepare(SQL.bumpRegistrationFence).get(userId, now) as {
      generation: number;
    };
    return row.generation;
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
