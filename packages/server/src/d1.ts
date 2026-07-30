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
  SessionIdentity,
} from './types.js';

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
import { LOCALWEBAUTHN_SCHEMA_VERSION, localWebAuthnSchemaStatements } from './schema.js';

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

export async function migrateD1(database: D1DatabaseLike, now = Date.now()): Promise<void> {
  await database.batch([
    ...localWebAuthnSchemaStatements().map((statement) => database.prepare(statement)),
    database
      .prepare(
        `INSERT OR IGNORE INTO localwebauthn_migrations(version, applied_at)
         VALUES (?, ?)`,
      )
      .bind(LOCALWEBAUTHN_SCHEMA_VERSION, now),
  ]);
}

function changes(result: D1ResultLike): number {
  return result.meta.changes ?? 0;
}

async function returningRow<Row>(statement: D1PreparedStatementLike): Promise<Row | null> {
  const result = await statement.run<Row>();
  return result.results[0] ?? null;
}

export class D1LocalWebAuthnStore implements LocalWebAuthnStore {
  readonly #database;

  constructor(database: D1DatabaseLike) {
    this.#database = database;
  }

  async replaceEnrollmentGrant(record: EnrollmentGrantRecord): Promise<string[]> {
    const revokedResult = await this.#database
      .prepare(
        `UPDATE localwebauthn_enrollment_grants
         SET revoked_at = ?
         WHERE user_id = ? AND completed_at IS NULL AND revoked_at IS NULL
         RETURNING id`,
      )
      .bind(record.createdAt, record.userId)
      .run<{ id: string }>();
    const revokedIds: string[] = revokedResult.results.map((row) => row.id);

    await this.#database
      .prepare(
        `INSERT INTO localwebauthn_enrollment_grants(
           id, user_id, token_hash, expires_at, approved_by_user_id, created_at
         ) VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        record.id,
        record.userId,
        record.tokenHash,
        record.expiresAt,
        record.approvedByUserId,
        record.createdAt,
      )
      .run();
    return revokedIds;
  }

  async exchangeEnrollment(
    tokenHash: Uint8Array,
    sessionHash: Uint8Array,
    sessionExpiresAt: number,
    now: number,
  ): Promise<EnrollmentSession | null> {
    const row = await returningRow<EnrollmentSessionRow>(
      this.#database
        .prepare(
          `UPDATE localwebauthn_enrollment_grants
           SET token_consumed_at = ?, session_hash = ?, session_expires_at = ?
           WHERE token_hash = ?
             AND token_consumed_at IS NULL
             AND completed_at IS NULL
             AND revoked_at IS NULL
             AND expires_at > ?
           RETURNING id, user_id, session_hash, session_expires_at`,
        )
        .bind(now, sessionHash, sessionExpiresAt, tokenHash, now),
    );
    return row ? enrollmentSessionFromRow(row) : null;
  }

  async resolveEnrollmentSession(
    sessionHash: Uint8Array,
    now: number,
  ): Promise<EnrollmentSession | null> {
    const row = await this.#database
      .prepare(
        `SELECT id, user_id, session_hash, session_expires_at
         FROM localwebauthn_enrollment_grants
         WHERE session_hash = ?
           AND session_expires_at > ?
           AND completed_at IS NULL
           AND revoked_at IS NULL`,
      )
      .bind(sessionHash, now)
      .first<EnrollmentSessionRow>();
    return row ? enrollmentSessionFromRow(row) : null;
  }

  async createChallenge(record: ChallengeRecord): Promise<boolean> {
    const result = await this.#database
      .prepare(
        `INSERT OR IGNORE INTO localwebauthn_challenges(
           id_hash, kind, challenge, user_id, grant_id,
           authorization_session_hash, expires_at, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        record.idHash,
        record.kind,
        record.challenge,
        record.userId,
        record.grantId,
        record.authorizationSessionHash,
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
      this.#database
        .prepare(
          `UPDATE localwebauthn_challenges
           SET consumed_at = ?
           WHERE id_hash = ?
             AND kind = ?
             AND consumed_at IS NULL
             AND expires_at > ?
           RETURNING kind, challenge, user_id, grant_id, authorization_session_hash`,
        )
        .bind(now, idHash, kind, now),
    );
    return row ? challengeFromRow(row) : null;
  }

  async listCredentials(userId: string, includeRevoked = false): Promise<Credential[]> {
    const result = await this.#database
      .prepare(
        `SELECT
           id, user_id, public_key, counter, transports_json, device_type,
           backed_up, label, created_at, last_used_at, revoked_at
         FROM localwebauthn_credentials
         WHERE user_id = ? AND (? = 1 OR revoked_at IS NULL)
         ORDER BY created_at, id`,
      )
      .bind(userId, includeRevoked ? 1 : 0)
      .all<CredentialRow>();
    return result.results.map(credentialFromRow);
  }

  async getCredential(credentialId: string): Promise<Credential | null> {
    const row = await this.#database
      .prepare(
        `SELECT
           id, user_id, public_key, counter, transports_json, device_type,
           backed_up, label, created_at, last_used_at, revoked_at
         FROM localwebauthn_credentials
         WHERE id = ?`,
      )
      .bind(credentialId)
      .first<CredentialRow>();
    return row ? credentialFromRow(row) : null;
  }

  async completeRegistration(input: CompleteRegistrationInput): Promise<boolean> {
    const { credential, challenge, enrollmentSessionHash, authenticatedSessionHash, session, now } =
      input;
    const grantId = challenge.grantId;
    const userId = credential.userId;
    const transportsJson = JSON.stringify(credential.transports);
    const backedUpInt = credential.backedUp ? 1 : 0;

    // Atomically insert the credential only while the authorizing grant or
    // session is still valid.  The single INSERT … SELECT … WHERE statement
    // checks one of two mutually-exclusive paths before writing:
    //
    //   Grant path  — grantId IS NOT NULL and the enrollment grant row is
    //                 uncompleted, unrevoked, and its session has not expired.
    //   Session path — grantId IS NULL, an authenticated session hash is
    //                 supplied, and that session (and its credential) are
    //                 still valid.
    //
    // Parameters are positional; the comments label each binding against the
    // `?` placeholders in the SQL above.
    const credentialInsert = this.#database
      .prepare(
        `INSERT INTO localwebauthn_credentials(
           id, user_id, public_key, counter, transports_json,
           device_type, backed_up, label, created_at
         )
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
         WHERE (
           ? IS NOT NULL
           AND EXISTS (
             SELECT 1 FROM localwebauthn_enrollment_grants
             WHERE id = ?
               AND user_id = ?
               AND session_hash = ?
               AND session_expires_at > ?
               AND completed_at IS NULL
               AND revoked_at IS NULL
           )
         ) OR (
           ? IS NULL
           AND ? IS NOT NULL
           AND EXISTS (
             SELECT 1
             FROM localwebauthn_sessions AS sessions
             JOIN localwebauthn_credentials AS credentials
               ON credentials.id = sessions.credential_id
             WHERE sessions.id_hash = ?
               AND sessions.user_id = ?
               AND sessions.expires_at > ?
               AND sessions.revoked_at IS NULL
               AND credentials.revoked_at IS NULL
           )
         )`,
      )
      .bind(
        /*  1 */ credential.id,
        /*  2 */ userId,
        /*  3 */ credential.publicKey,
        /*  4 */ credential.counter,
        /*  5 */ transportsJson,
        /*  6 */ credential.deviceType,
        /*  7 */ backedUpInt,
        /*  8 */ credential.label,
        /*  9 */ credential.createdAt,
        /* 10 */ grantId, // also used as the "IS NOT NULL" condition for the grant path
        /* 11 */ grantId, // sub-query: enrollment grant id match
        /* 12 */ userId, // sub-query: user match
        /* 13 */ enrollmentSessionHash, // sub-query: session hash match
        /* 14 */ now, // sub-query: session not expired
        /* 15 */ grantId, // also used as the "IS NULL" condition for the session path
        /* 16 */ authenticatedSessionHash, // also used as the "IS NOT NULL" condition
        /* 17 */ authenticatedSessionHash, // sub-query: session id_hash match
        /* 18 */ userId, // sub-query: user match
        /* 19 */ now, // sub-query: session not expired
      );

    const statements: D1PreparedStatementLike[] = [credentialInsert, this.#guardPreviousChange()];

    // If this was a grant-based enrollment, mark the grant as completed.
    // The guard above ensures the credential insert succeeded before we
    // attempt this update.
    if (grantId) {
      statements.push(
        this.#database
          .prepare(
            `UPDATE localwebauthn_enrollment_grants
             SET completed_at = ?
             WHERE id = ?
               AND session_hash = ?
               AND session_expires_at > ?
               AND completed_at IS NULL
               AND revoked_at IS NULL`,
          )
          .bind(
            /* 1 */ now,
            /* 2 */ grantId,
            /* 3 */ enrollmentSessionHash,
            /* 4 */ now, // session still valid
          ),
        this.#guardPreviousChange(),
      );
    }

    statements.push(
      this.#insertSessionStatement(session),
      this.#guardPreviousChange(),
      this.#database.prepare('DELETE FROM localwebauthn_transaction_guard'),
    );

    try {
      await this.#database.batch(statements);
      return true;
    } catch {
      return false;
    }
  }

  async completeAuthentication(input: CompleteAuthenticationInput): Promise<boolean> {
    try {
      await this.#database.batch([
        this.#database
          .prepare(
            `UPDATE localwebauthn_credentials
             SET counter = ?, last_used_at = ?
             WHERE id = ? AND counter = ? AND revoked_at IS NULL`,
          )
          .bind(input.newCounter, input.now, input.credentialId, input.previousCounter),
        this.#guardPreviousChange(),
        this.#insertSessionStatement(input.session),
        this.#guardPreviousChange(),
        this.#database.prepare('DELETE FROM localwebauthn_transaction_guard'),
      ]);
      return true;
    } catch {
      return false;
    }
  }

  async resolveSession(
    idHash: Uint8Array,
    now: number,
    idleExpiresBefore: number,
  ): Promise<SessionIdentity | null> {
    const row = await this.#database
      .prepare(
        `SELECT
           sessions.user_id, sessions.credential_id, sessions.authenticated_at,
           sessions.expires_at, sessions.last_seen_at
         FROM localwebauthn_sessions AS sessions
         JOIN localwebauthn_credentials AS credentials
           ON credentials.id = sessions.credential_id
         WHERE sessions.id_hash = ?
           AND sessions.expires_at > ?
           AND sessions.last_seen_at > ?
           AND sessions.revoked_at IS NULL
           AND credentials.revoked_at IS NULL`,
      )
      .bind(idHash, now, idleExpiresBefore)
      .first<SessionRow>();
    return row ? sessionFromRow(row) : null;
  }

  async touchSession(idHash: Uint8Array, now: number): Promise<boolean> {
    const result = await this.#database
      .prepare(
        `UPDATE localwebauthn_sessions
         SET last_seen_at = ?
         WHERE id_hash = ? AND revoked_at IS NULL AND expires_at > ?`,
      )
      .bind(now, idHash, now)
      .run();
    return changes(result) === 1;
  }

  async revokeSession(idHash: Uint8Array, now: number): Promise<boolean> {
    const result = await this.#database
      .prepare(
        `UPDATE localwebauthn_sessions
         SET revoked_at = ?
         WHERE id_hash = ? AND revoked_at IS NULL`,
      )
      .bind(now, idHash)
      .run();
    return changes(result) === 1;
  }

  async revokeCredential(userId: string, credentialId: string, now: number): Promise<boolean> {
    const results = await this.#database.batch([
      this.#database
        .prepare(
          `UPDATE localwebauthn_credentials
           SET revoked_at = ?
           WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
        )
        .bind(now, credentialId, userId),
      this.#database
        .prepare(
          `UPDATE localwebauthn_sessions
           SET revoked_at = ?
           WHERE credential_id = ? AND revoked_at IS NULL`,
        )
        .bind(now, credentialId),
    ]);
    return changes(results[0]) === 1;
  }

  async revokeUserAuthentication(userId: string, now: number): Promise<void> {
    await this.#database.batch([
      this.#database
        .prepare(
          `UPDATE localwebauthn_credentials
           SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
        )
        .bind(now, userId),
      this.#database
        .prepare(
          `UPDATE localwebauthn_sessions
           SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
        )
        .bind(now, userId),
      this.#database
        .prepare(
          `UPDATE localwebauthn_enrollment_grants
           SET revoked_at = ?
           WHERE user_id = ? AND completed_at IS NULL AND revoked_at IS NULL`,
        )
        .bind(now, userId),
      this.#database
        .prepare(
          `UPDATE localwebauthn_challenges
           SET consumed_at = ?
           WHERE user_id = ? AND consumed_at IS NULL`,
        )
        .bind(now, userId),
    ]);
  }

  async cleanup(now: number): Promise<CleanupResult> {
    // D1 batches are not atomic. A credential INSERT can succeed while the
    // subsequent session INSERT is never reached (mid-batch guard failure).
    // Remove credentials that have no session rows and are old enough to be
    // certain they are orphans, not in-flight registrations.
    const orphanedCredentialCutoff = now - 3_600_000; // 1 hour grace period
    const results = await this.#database.batch([
      this.#database
        .prepare(
          `DELETE FROM localwebauthn_enrollment_grants
           WHERE (expires_at <= ? OR completed_at IS NOT NULL OR revoked_at IS NOT NULL)
             AND id NOT IN (
               SELECT grant_id FROM localwebauthn_challenges WHERE grant_id IS NOT NULL
             )`,
        )
        .bind(now),
      this.#database
        .prepare(
          `DELETE FROM localwebauthn_challenges
           WHERE expires_at <= ? OR consumed_at IS NOT NULL`,
        )
        .bind(now),
      this.#database
        .prepare(
          `DELETE FROM localwebauthn_sessions
           WHERE expires_at <= ? OR revoked_at IS NOT NULL`,
        )
        .bind(now),
      this.#database
        .prepare(
          `DELETE FROM localwebauthn_credentials
           WHERE id NOT IN (SELECT DISTINCT credential_id FROM localwebauthn_sessions)
             AND created_at <= ?`,
        )
        .bind(orphanedCredentialCutoff),
    ]);
    return {
      enrollmentGrants: changes(results[0]),
      challenges: changes(results[1]),
      sessions: changes(results[2]),
      orphanedCredentials: changes(results[3]),
    };
  }

  #guardPreviousChange(): D1PreparedStatementLike {
    return this.#database.prepare(
      'INSERT INTO localwebauthn_transaction_guard(value) VALUES (changes())',
    );
  }

  #insertSessionStatement(session: CompleteRegistrationInput['session']): D1PreparedStatementLike {
    return this.#database
      .prepare(
        `INSERT INTO localwebauthn_sessions(
           id_hash, user_id, credential_id, authenticated_at, expires_at, last_seen_at
         ) VALUES (?, ?, ?, ?, ?, ?)`,
      )
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
