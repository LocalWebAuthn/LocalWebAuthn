import {
  challengeFromRow,
  credentialFromRow,
  enrollmentSessionFromRow,
  sessionFromRow
} from "./chunk-QN7KH2GR.js";
import {
  LOCALWEBAUTHN_SCHEMA_VERSION,
  localWebAuthnSchemaStatements
} from "./chunk-YGBWJ5OU.js";

// src/d1.ts
async function migrateD1(database, now = Date.now()) {
  await database.batch([
    ...localWebAuthnSchemaStatements().map((statement) => database.prepare(statement)),
    database.prepare(
      `INSERT OR IGNORE INTO localwebauthn_migrations(version, applied_at)
         VALUES (?, ?)`
    ).bind(LOCALWEBAUTHN_SCHEMA_VERSION, now)
  ]);
}
function changes(result) {
  return result.meta.changes ?? 0;
}
async function returningRow(statement) {
  const result = await statement.run();
  return result.results[0] ?? null;
}
var D1LocalWebAuthnStore = class {
  #database;
  constructor(database) {
    this.#database = database;
  }
  async replaceEnrollmentGrant(record) {
    const revokedResult = await this.#database.prepare(
      `UPDATE localwebauthn_enrollment_grants
         SET revoked_at = ?
         WHERE user_id = ? AND completed_at IS NULL AND revoked_at IS NULL
         RETURNING id`
    ).bind(record.createdAt, record.userId).run();
    const revokedIds = revokedResult.results.map((row) => row.id);
    await this.#database.prepare(
      `INSERT INTO localwebauthn_enrollment_grants(
           id, user_id, token_hash, expires_at, approved_by_user_id, created_at
         ) VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(
      record.id,
      record.userId,
      record.tokenHash,
      record.expiresAt,
      record.approvedByUserId,
      record.createdAt
    ).run();
    return revokedIds;
  }
  async exchangeEnrollment(tokenHash, sessionHash, sessionExpiresAt, now) {
    const row = await returningRow(
      this.#database.prepare(
        `UPDATE localwebauthn_enrollment_grants
           SET token_consumed_at = ?, session_hash = ?, session_expires_at = ?
           WHERE token_hash = ?
             AND token_consumed_at IS NULL
             AND completed_at IS NULL
             AND revoked_at IS NULL
             AND expires_at > ?
           RETURNING id, user_id, session_hash, session_expires_at`
      ).bind(now, sessionHash, sessionExpiresAt, tokenHash, now)
    );
    return row ? enrollmentSessionFromRow(row) : null;
  }
  async resolveEnrollmentSession(sessionHash, now) {
    const row = await this.#database.prepare(
      `SELECT id, user_id, session_hash, session_expires_at
         FROM localwebauthn_enrollment_grants
         WHERE session_hash = ?
           AND session_expires_at > ?
           AND completed_at IS NULL
           AND revoked_at IS NULL`
    ).bind(sessionHash, now).first();
    return row ? enrollmentSessionFromRow(row) : null;
  }
  async createChallenge(record) {
    await this.#database.prepare(
      `INSERT INTO localwebauthn_challenges(
           id_hash, kind, challenge, user_id, grant_id,
           authorization_session_hash, expires_at, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      record.idHash,
      record.kind,
      record.challenge,
      record.userId,
      record.grantId,
      record.authorizationSessionHash,
      record.expiresAt,
      record.createdAt
    ).run();
  }
  async consumeChallenge(idHash, kind, now) {
    const row = await returningRow(
      this.#database.prepare(
        `UPDATE localwebauthn_challenges
           SET consumed_at = ?
           WHERE id_hash = ?
             AND kind = ?
             AND consumed_at IS NULL
             AND expires_at > ?
           RETURNING kind, challenge, user_id, grant_id, authorization_session_hash`
      ).bind(now, idHash, kind, now)
    );
    return row ? challengeFromRow(row) : null;
  }
  async listCredentials(userId, includeRevoked = false) {
    const result = await this.#database.prepare(
      `SELECT
           id, user_id, public_key, counter, transports_json, device_type,
           backed_up, label, created_at, last_used_at, revoked_at
         FROM localwebauthn_credentials
         WHERE user_id = ? AND (? = 1 OR revoked_at IS NULL)
         ORDER BY created_at, id`
    ).bind(userId, includeRevoked ? 1 : 0).all();
    return result.results.map(credentialFromRow);
  }
  async getCredential(credentialId) {
    const row = await this.#database.prepare(
      `SELECT
           id, user_id, public_key, counter, transports_json, device_type,
           backed_up, label, created_at, last_used_at, revoked_at
         FROM localwebauthn_credentials
         WHERE id = ?`
    ).bind(credentialId).first();
    return row ? credentialFromRow(row) : null;
  }
  async completeRegistration(input) {
    const credential = input.credential;
    const grantId = input.challenge.grantId;
    const grantSessionHash = input.enrollmentSessionHash;
    const authenticatedSessionHash = input.authenticatedSessionHash;
    const statements = [
      this.#database.prepare(
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
           )`
      ).bind(
        credential.id,
        credential.userId,
        credential.publicKey,
        credential.counter,
        JSON.stringify(credential.transports),
        credential.deviceType,
        credential.backedUp ? 1 : 0,
        credential.label,
        credential.createdAt,
        grantId,
        grantId,
        credential.userId,
        grantSessionHash,
        input.now,
        grantId,
        authenticatedSessionHash,
        authenticatedSessionHash,
        credential.userId,
        input.now
      ),
      this.#guardPreviousChange()
    ];
    if (grantId) {
      statements.push(
        this.#database.prepare(
          `UPDATE localwebauthn_enrollment_grants
             SET completed_at = ?
             WHERE id = ?
               AND session_hash = ?
               AND session_expires_at > ?
               AND completed_at IS NULL
               AND revoked_at IS NULL`
        ).bind(input.now, grantId, grantSessionHash, input.now),
        this.#guardPreviousChange()
      );
    }
    statements.push(
      this.#insertSessionStatement(input.session),
      this.#guardPreviousChange(),
      this.#database.prepare("DELETE FROM localwebauthn_transaction_guard")
    );
    try {
      await this.#database.batch(statements);
      return true;
    } catch {
      return false;
    }
  }
  async completeAuthentication(input) {
    try {
      await this.#database.batch([
        this.#database.prepare(
          `UPDATE localwebauthn_credentials
             SET counter = ?, last_used_at = ?
             WHERE id = ? AND counter = ? AND revoked_at IS NULL`
        ).bind(input.newCounter, input.now, input.credentialId, input.previousCounter),
        this.#guardPreviousChange(),
        this.#insertSessionStatement(input.session),
        this.#guardPreviousChange(),
        this.#database.prepare("DELETE FROM localwebauthn_transaction_guard")
      ]);
      return true;
    } catch {
      return false;
    }
  }
  async resolveSession(idHash, now, idleExpiresBefore) {
    const row = await this.#database.prepare(
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
           AND credentials.revoked_at IS NULL`
    ).bind(idHash, now, idleExpiresBefore).first();
    return row ? sessionFromRow(row) : null;
  }
  async touchSession(idHash, now) {
    const result = await this.#database.prepare(
      `UPDATE localwebauthn_sessions
         SET last_seen_at = ?
         WHERE id_hash = ? AND revoked_at IS NULL AND expires_at > ?`
    ).bind(now, idHash, now).run();
    return changes(result) === 1;
  }
  async revokeSession(idHash, now) {
    const result = await this.#database.prepare(
      `UPDATE localwebauthn_sessions
         SET revoked_at = ?
         WHERE id_hash = ? AND revoked_at IS NULL`
    ).bind(now, idHash).run();
    return changes(result) === 1;
  }
  async revokeCredential(userId, credentialId, now) {
    const results = await this.#database.batch([
      this.#database.prepare(
        `UPDATE localwebauthn_credentials
           SET revoked_at = ?
           WHERE id = ? AND user_id = ? AND revoked_at IS NULL`
      ).bind(now, credentialId, userId),
      this.#database.prepare(
        `UPDATE localwebauthn_sessions
           SET revoked_at = ?
           WHERE credential_id = ? AND revoked_at IS NULL`
      ).bind(now, credentialId)
    ]);
    return changes(results[0]) === 1;
  }
  async revokeUserAuthentication(userId, now) {
    await this.#database.batch([
      this.#database.prepare(
        `UPDATE localwebauthn_credentials
           SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`
      ).bind(now, userId),
      this.#database.prepare(
        `UPDATE localwebauthn_sessions
           SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`
      ).bind(now, userId),
      this.#database.prepare(
        `UPDATE localwebauthn_enrollment_grants
           SET revoked_at = ?
           WHERE user_id = ? AND completed_at IS NULL AND revoked_at IS NULL`
      ).bind(now, userId),
      this.#database.prepare(
        `UPDATE localwebauthn_challenges
           SET consumed_at = ?
           WHERE user_id = ? AND consumed_at IS NULL`
      ).bind(now, userId)
    ]);
  }
  async cleanup(now) {
    const orphanedCredentialCutoff = now - 36e5;
    const results = await this.#database.batch([
      this.#database.prepare(
        `DELETE FROM localwebauthn_enrollment_grants
           WHERE (expires_at <= ? OR completed_at IS NOT NULL OR revoked_at IS NOT NULL)
             AND id NOT IN (
               SELECT grant_id FROM localwebauthn_challenges WHERE grant_id IS NOT NULL
             )`
      ).bind(now),
      this.#database.prepare(
        `DELETE FROM localwebauthn_challenges
           WHERE expires_at <= ? OR consumed_at IS NOT NULL`
      ).bind(now),
      this.#database.prepare(
        `DELETE FROM localwebauthn_sessions
           WHERE expires_at <= ? OR revoked_at IS NOT NULL`
      ).bind(now),
      this.#database.prepare(
        `DELETE FROM localwebauthn_credentials
           WHERE id NOT IN (SELECT DISTINCT credential_id FROM localwebauthn_sessions)
             AND created_at <= ?`
      ).bind(orphanedCredentialCutoff)
    ]);
    return {
      enrollmentGrants: changes(results[0]),
      challenges: changes(results[1]),
      sessions: changes(results[2]),
      orphanedCredentials: changes(results[3])
    };
  }
  #guardPreviousChange() {
    return this.#database.prepare(
      "INSERT INTO localwebauthn_transaction_guard(value) VALUES (changes())"
    );
  }
  #insertSessionStatement(session) {
    return this.#database.prepare(
      `INSERT INTO localwebauthn_sessions(
           id_hash, user_id, credential_id, authenticated_at, expires_at, last_seen_at
         ) VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(
      session.idHash,
      session.userId,
      session.credentialId,
      session.authenticatedAt,
      session.expiresAt,
      session.lastSeenAt
    );
  }
};
export {
  D1LocalWebAuthnStore,
  migrateD1
};
