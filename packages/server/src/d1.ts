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
  LocalWebAuthnDpopStore,
  LocalWebAuthnStore,
  NewCredential,
  NewSession,
  RevokeCredentialResult,
  RevokedSession,
  SessionIdentity,
} from './types.js';

import { D1_SQL, SQL } from './queries.js';
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
import {
  LOCALWEBAUTHN_SCHEMA_VERSION,
  localWebAuthnMigrationsTableStatement,
  localWebAuthnUpgradeStatements,
} from './schema.js';

export type D1ResultLike<Row = Record<string, unknown>> = {
  results: Row[];
  success: boolean;
  meta: {
    changes?: number;
  };
};

export type D1PreparedStatementLike = {
  bind(...values: unknown[]): D1PreparedStatementLike;
  first<Row = Record<string, unknown>>(): Promise<Row | null>;
  all<Row = Record<string, unknown>>(): Promise<D1ResultLike<Row>>;
  run<Row = Record<string, unknown>>(): Promise<D1ResultLike<Row>>;
};

export type D1DatabaseLike = {
  prepare(sql: string): D1PreparedStatementLike;
  batch(statements: D1PreparedStatementLike[]): Promise<D1ResultLike[]>;
  exec(sql: string): Promise<unknown>;
};

/**
 * Create or upgrade the `localwebauthn_*` tables. Idempotent — safe to call on
 * every deploy.
 *
 * Version-aware, exactly like {@link migrateSqlite} and {@link migratePostgres}:
 * it reads the stored schema version and applies only what is missing. The
 * previous implementation ran the current full schema blind, so on a released v1
 * database the `CREATE TABLE IF NOT EXISTS` statements were no-ops, the v1→v2
 * `ALTER TABLE`s never ran, and the first index over a v2-only column
 * (`localwebauthn_credential_kind_idx`) failed against a column that did not
 * exist — a v1 D1 deployment could not upgrade at all.
 *
 * A D1 `batch()` is one implicit transaction: a failing statement aborts and
 * rolls back the whole sequence
 * (https://developers.cloudflare.com/d1/worker-api/d1-database/). So the upgrade
 * DDL and the version stamp that records it commit together or not at all — a
 * half-applied schema is never observable.
 */
export async function migrateD1(database: D1DatabaseLike, now = Date.now()): Promise<void> {
  // The version table has to exist before its own version can be read. This one
  // statement is idempotent and dialect-correct for D1's SQLite.
  await database.prepare(localWebAuthnMigrationsTableStatement()).run();

  const from = await installedD1Version(database);
  if (from >= LOCALWEBAUTHN_SCHEMA_VERSION) {
    return;
  }

  const upgrade = localWebAuthnUpgradeStatements(from, 'sqlite');
  try {
    await database.batch([
      ...upgrade.map((statement) => database.prepare(statement)),
      database.prepare(SQL.insertMigration).bind(LOCALWEBAUTHN_SCHEMA_VERSION, now),
    ]);
  } catch (error) {
    // Two workers can begin the same upgrade at once; the loser's `ADD COLUMN`
    // statements fail ("duplicate column name") and its batch rolls back. That is
    // a won race, not corruption — provided the database is now at the target
    // version. Re-read to distinguish the two.
    if ((await installedD1Version(database)) >= LOCALWEBAUTHN_SCHEMA_VERSION) {
      return;
    }
    throw error;
  }
}

async function installedD1Version(database: D1DatabaseLike): Promise<number> {
  const row = await database.prepare(SQL.selectSchemaVersion).first<{ version: number | null }>();
  return row?.version ?? 0;
}

/**
 * Whether a failed batch was stopped by the transaction guard — the CHECK row
 * that fails when a step changed no rows, i.e. authorization or the counter
 * compare-and-swap was lost mid-batch. That case reports `false`; every other
 * exception is a real storage fault the host must see, not an expired
 * enrollment. (#6)
 */
function guardTripped(error: unknown): false {
  if (String(error).includes('CHECK constraint failed')) {
    return false;
  }
  throw error;
}

function changes(result: D1ResultLike): number {
  return result.meta.changes ?? 0;
}

async function returningRow<Row>(statement: D1PreparedStatementLike): Promise<Row | null> {
  const result = await statement.run<Row>();
  return result.results[0] ?? null;
}

/**
 * {@link LocalWebAuthnStore} backed by Cloudflare D1.
 *
 * Multi-statement operations run as a `batch()`, which D1 executes as one
 * transaction: a failing statement aborts and rolls the whole sequence back
 * (https://developers.cloudflare.com/d1/worker-api/d1-database/). Every step that
 * must affect exactly one row is followed by a guard statement whose CHECK fails
 * the batch otherwise, so an unauthorized write rolls the batch back rather than
 * committing partially. See the D1 section of `SECURITY.md`. Schedule
 * {@link D1LocalWebAuthnStore.cleanup} to reap expired grants, challenges, and
 * sessions.
 */
export class D1LocalWebAuthnStore implements LocalWebAuthnStore, LocalWebAuthnDpopStore {
  readonly #database;

  constructor(database: D1DatabaseLike) {
    this.#database = database;
  }

  async replaceEnrollmentGrant(record: EnrollmentGrantRecord): Promise<string[]> {
    // Kind-scoped: replacing a person's pending link must not cancel a pending
    // deployment-key grant, or vice versa.
    const revoked = await this.#database
      .prepare(SQL.revokePendingGrants)
      .bind(record.createdAt, record.userId, record.credentialKind)
      .run<{ id: string }>();

    await this.#database
      .prepare(SQL.insertEnrollmentGrant)
      .bind(
        record.id,
        record.userId,
        record.tokenHash,
        record.expiresAt,
        record.approvedByUserId,
        record.credentialKind,
        record.createdAt,
      )
      .run();
    return revoked.results.map((row) => row.id);
  }

  async revokePendingEnrollmentGrants(
    userId: string,
    now: number,
    credentialKind: string | null,
  ): Promise<string[]> {
    const result = await this.#database
      .prepare(SQL.revokePendingGrants)
      .bind(now, userId, credentialKind)
      .all<{ id: string }>();
    return result.results.map((row) => row.id);
  }

  async exchangeEnrollment(
    tokenHash: Uint8Array,
    sessionHash: Uint8Array,
    sessionExpiresAt: number,
    now: number,
  ): Promise<EnrollmentSession | null> {
    const row = await returningRow<EnrollmentSessionRow>(
      this.#database
        .prepare(SQL.exchangeEnrollment)
        .bind(now, sessionHash, sessionExpiresAt, tokenHash, now),
    );
    return row ? enrollmentSessionFromRow(row) : null;
  }

  async resolveEnrollmentSession(
    sessionHash: Uint8Array,
    now: number,
  ): Promise<EnrollmentSession | null> {
    const row = await this.#database
      .prepare(SQL.selectEnrollmentSession)
      .bind(sessionHash, now)
      .first<EnrollmentSessionRow>();
    return row ? enrollmentSessionFromRow(row) : null;
  }

  async createChallenge(record: ChallengeRecord): Promise<boolean> {
    const result = await this.#database
      .prepare(SQL.insertChallenge)
      .bind(
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
      )
      .run();
    return changes(result) === 1;
  }

  async consumeChallenge(
    idHash: Uint8Array,
    kind: ChallengeKind,
    now: number,
  ): Promise<ConsumedChallenge | null> {
    const row = await returningRow<ChallengeRow>(
      this.#database.prepare(SQL.consumeChallenge).bind(now, idHash, kind, now),
    );
    return row ? challengeFromRow(row) : null;
  }

  async listCredentials(userId: string, includeRevoked = false): Promise<Credential[]> {
    const result = await this.#database
      .prepare(SQL.selectCredentialsForUser)
      .bind(userId, includeRevoked ? 1 : 0)
      .all<CredentialRow>();
    return result.results.map(credentialFromRow);
  }

  async getCredential(credentialId: string): Promise<Credential | null> {
    const row = await this.#database
      .prepare(SQL.selectCredentialById)
      .bind(credentialId)
      .first<CredentialRow>();
    return row ? credentialFromRow(row) : null;
  }

  async credentialAncestry(userId: string, credentialId: string): Promise<Credential[]> {
    const result = await this.#database
      .prepare(SQL.selectCredentialAncestry)
      .bind(credentialId, userId)
      .all<CredentialRow>();
    return result.results.map(credentialFromRow);
  }

  async credentialDescendants(userId: string, credentialId: string): Promise<Credential[]> {
    const result = await this.#database
      .prepare(SQL.selectCredentialDescendants)
      .bind(credentialId, userId)
      .all<CredentialRow>();
    return result.results.map(credentialFromRow);
  }

  async completeRegistration(input: CompleteRegistrationInput): Promise<boolean> {
    const { credential, challenge, enrollmentSessionHash, authenticatedSessionHash, session, now } =
      input;
    const grantId = challenge.grantId;

    // Insert the credential only while its authorization still holds. Which of
    // the two statements applies is decided here, not inside the SQL.
    let credentialInsert: D1PreparedStatementLike;
    if (grantId && enrollmentSessionHash) {
      credentialInsert = this.#database
        .prepare(D1_SQL.insertCredentialIfGrantValid)
        .bind(
          ...this.#credentialValues(credential),
          grantId,
          credential.userId,
          enrollmentSessionHash,
          now,
        );
    } else if (challenge.authorizationSessionHash && authenticatedSessionHash) {
      credentialInsert = this.#database
        .prepare(D1_SQL.insertCredentialIfSessionValid)
        .bind(
          ...this.#credentialValues(credential),
          authenticatedSessionHash,
          credential.userId,
          now,
        );
    } else {
      return false;
    }

    // The registration fence goes first: if a revoke has advanced the user's
    // generation since this challenge was issued, the guard inserts 0, the CHECK
    // fails, and the whole batch — credential included — rolls back.
    const statements =
      challenge.registrationGeneration === null
        ? [credentialInsert, this.#guard()]
        : [
            this.#database
              .prepare(D1_SQL.guardRegistrationFence)
              .bind(credential.userId, challenge.registrationGeneration),
            credentialInsert,
            this.#guard(),
          ];

    // A grant-based registration also closes the grant. The guard above has
    // already established that the credential insert affected one row.
    if (grantId) {
      statements.push(
        this.#database
          .prepare(SQL.completeEnrollmentGrant)
          .bind(now, grantId, enrollmentSessionHash, now),
        this.#guard(),
      );
    }

    statements.push(
      this.#insertSessionStatement(session),
      this.#guard(),
      this.#database.prepare(D1_SQL.clearGuard),
    );

    try {
      await this.#database.batch(statements);
      return true;
    } catch (error) {
      return guardTripped(error);
    }
  }

  async completeAuthentication(input: CompleteAuthenticationInput): Promise<boolean> {
    try {
      await this.#database.batch([
        this.#database
          .prepare(SQL.advanceCredentialCounter)
          .bind(
            input.newCounter,
            input.now,
            input.credentialId,
            input.previousCounter,
            input.newCounter,
            input.newCounter,
          ),
        this.#guard(),
        this.#insertSessionStatement(input.session),
        this.#guard(),
        this.#database.prepare(D1_SQL.clearGuard),
      ]);
      return true;
    } catch (error) {
      return guardTripped(error);
    }
  }

  async resolveSession(
    idHash: Uint8Array,
    now: number,
    idleExpiresBefore: number,
  ): Promise<SessionIdentity | null> {
    const row = await this.#database
      .prepare(SQL.selectSession)
      .bind(idHash, now, idleExpiresBefore)
      .first<SessionRow>();
    return row ? sessionFromRow(row) : null;
  }

  async touchSession(idHash: Uint8Array, now: number): Promise<boolean> {
    const result = await this.#database.prepare(SQL.touchSession).bind(now, idHash, now).run();
    return changes(result) === 1;
  }

  async revokeSession(idHash: Uint8Array, now: number): Promise<RevokedSession | null> {
    const row = await returningRow<{ user_id: string; credential_id: string }>(
      this.#database.prepare(SQL.revokeSession).bind(now, idHash),
    );
    return row ? { userId: row.user_id, credentialId: row.credential_id } : null;
  }

  async revokeUserSessions(
    userId: string,
    now: number,
    idleExpiresBefore: number,
    exceptSessionHash?: Uint8Array,
  ): Promise<number> {
    // A single conditional UPDATE, so D1 needs no transaction here.
    const statement = exceptSessionHash
      ? this.#database
          .prepare(SQL.revokeLiveUserSessionsExcept)
          .bind(now, userId, now, idleExpiresBefore, exceptSessionHash)
      : this.#database
          .prepare(SQL.revokeLiveUserSessions)
          .bind(now, userId, now, idleExpiresBefore);
    return changes(await statement.run());
  }

  async revokeCredential(
    userId: string,
    credentialId: string,
    now: number,
    options: { allowLastCredential?: boolean } = {},
  ): Promise<RevokeCredentialResult> {
    const allowLast = options.allowLastCredential ? 1 : 0;
    // Conditional UPDATE encodes last-credential protection in one statement so
    // D1 does not need a transaction for the predicate.
    const results = await this.#database.batch([
      this.#database
        .prepare(SQL.revokeCredential)
        .bind(now, credentialId, userId, allowLast, userId, credentialId),
      this.#database.prepare(SQL.revokeSessionsForCredential).bind(now, credentialId),
    ]);
    if (changes(results[0]) === 1) {
      return 'revoked';
    }
    if (!options.allowLastCredential) {
      const last = await this.#database
        .prepare(SQL.isLastActiveCredential)
        .bind(credentialId, userId, userId, credentialId)
        .first();
      if (last) {
        return 'last_credential';
      }
    }
    return 'not_found';
  }

  async revokeUserAuthentication(userId: string, now: number): Promise<void> {
    await this.#database.batch([
      this.#database.prepare(SQL.revokeUserCredentials).bind(now, userId),
      this.#database.prepare(SQL.revokeUserSessions).bind(now, userId),
      this.#database.prepare(SQL.revokeUserGrants).bind(now, userId),
      this.#database.prepare(SQL.consumeUserChallenges).bind(now, userId),
    ]);
  }

  async cleanup(now: number): Promise<CleanupResult> {
    const results = await this.#database.batch([
      this.#database.prepare(SQL.deleteExpiredSessions).bind(now),
      this.#database.prepare(SQL.deleteFinishedGrants).bind(now),
      this.#database.prepare(SQL.deleteFinishedChallenges).bind(now),
      this.#database.prepare(SQL.deleteExpiredDpopProofs).bind(now),
      this.#database.prepare(SQL.deleteExpiredDpopNonces).bind(now),
    ]);
    return {
      sessions: changes(results[0]),
      enrollmentGrants: changes(results[1]),
      challenges: changes(results[2]),
      dpopProofs: changes(results[3]),
      dpopNonces: changes(results[4]),
    };
  }

  async registrationGeneration(userId: string, now: number): Promise<number> {
    await this.#database.prepare(SQL.ensureRegistrationFence).bind(userId, now).run();
    const row = await this.#database
      .prepare(SQL.selectRegistrationFence)
      .bind(userId)
      .first<{ generation: number }>();
    return row?.generation ?? 0;
  }

  async bumpRegistrationGeneration(userId: string, now: number): Promise<number> {
    const row = await this.#database
      .prepare(SQL.bumpRegistrationFence)
      .bind(userId, now)
      .first<{ generation: number }>();
    return row?.generation ?? 0;
  }

  async claimDpopProof(jtiHash: Uint8Array, expiresAt: number): Promise<boolean> {
    const result = await this.#database.prepare(SQL.claimDpopProof).bind(jtiHash, expiresAt).run();
    return changes(result) === 1;
  }

  async revokeLiveCredentialSessions(
    credentialId: string,
    now: number,
    idleExpiresBefore: number,
    exceptSessionHash?: Uint8Array,
  ): Promise<number> {
    const statement = exceptSessionHash
      ? this.#database
          .prepare(SQL.revokeLiveCredentialSessionsExcept)
          .bind(now, credentialId, now, idleExpiresBefore, exceptSessionHash)
      : this.#database
          .prepare(SQL.revokeLiveCredentialSessions)
          .bind(now, credentialId, now, idleExpiresBefore);
    return changes(await statement.run());
  }

  async claimDpopNonce(slot: number, candidate: string, expiresAt: number): Promise<string> {
    await this.#database.prepare(SQL.insertDpopNonce).bind(slot, candidate, expiresAt).run();
    const row = await this.#database
      .prepare(SQL.selectDpopNonce)
      .bind(slot)
      .first<{ nonce: string }>();
    return row?.nonce ?? candidate;
  }

  async dpopNonces(currentSlot: number, previousSlot: number): Promise<string[]> {
    const result = await this.#database
      .prepare(SQL.selectDpopNonces)
      .bind(currentSlot, previousSlot)
      .all<{ nonce: string }>();
    return result.results.map((row) => row.nonce);
  }

  /** The ten `localwebauthn_credentials` column values, in schema order. */
  #credentialValues(credential: NewCredential): unknown[] {
    return [
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
    ];
  }

  #guard(): D1PreparedStatementLike {
    return this.#database.prepare(D1_SQL.guardPreviousChange);
  }

  #insertSessionStatement(session: NewSession): D1PreparedStatementLike {
    return this.#database
      .prepare(SQL.insertSession)
      .bind(
        session.idHash,
        session.userId,
        session.credentialId,
        session.authenticatedAt,
        session.expiresAt,
        session.lastSeenAt,
      );
  }
}
