import {
  challengeFromRow,
  credentialFromRow,
  enrollmentSessionFromRow,
  sessionFromRow
} from "./chunk-QN7KH2GR.js";
import {
  LOCALWEBAUTHN_SCHEMA_SQL,
  LOCALWEBAUTHN_SCHEMA_VERSION
} from "./chunk-YGBWJ5OU.js";

// src/sqlite.ts
function migrateSqlite(database, now = Date.now()) {
  database.transaction(() => {
    database.exec(LOCALWEBAUTHN_SCHEMA_SQL);
    database.prepare(
      `INSERT OR IGNORE INTO localwebauthn_migrations(version, applied_at)
         VALUES (?, ?)`
    ).run(LOCALWEBAUTHN_SCHEMA_VERSION, now);
  })();
}
var SqliteLocalWebAuthnStore = class {
  #database;
  constructor(database) {
    this.#database = database;
  }
  async replaceEnrollmentGrant(record) {
    this.#database.transaction(() => {
      this.#database.prepare(
        `UPDATE localwebauthn_enrollment_grants
           SET revoked_at = ?
           WHERE user_id = ? AND completed_at IS NULL AND revoked_at IS NULL`
      ).run(record.createdAt, record.userId);
      this.#database.prepare(
        `INSERT INTO localwebauthn_enrollment_grants(
             id, user_id, token_hash, expires_at, approved_by_user_id, created_at
           ) VALUES (?, ?, ?, ?, ?, ?)`
      ).run(
        record.id,
        record.userId,
        record.tokenHash,
        record.expiresAt,
        record.approvedByUserId,
        record.createdAt
      );
    })();
  }
  async exchangeEnrollment(tokenHash, sessionHash, sessionExpiresAt, now) {
    return this.#database.transaction(() => {
      const row = this.#database.prepare(
        `SELECT id, user_id
           FROM localwebauthn_enrollment_grants
           WHERE token_hash = ?
             AND token_consumed_at IS NULL
             AND completed_at IS NULL
             AND revoked_at IS NULL
             AND expires_at > ?`
      ).get(tokenHash, now);
      if (!row) {
        return null;
      }
      const update = this.#database.prepare(
        `UPDATE localwebauthn_enrollment_grants
           SET token_consumed_at = ?, session_hash = ?, session_expires_at = ?
           WHERE id = ? AND token_consumed_at IS NULL AND revoked_at IS NULL`
      ).run(now, sessionHash, sessionExpiresAt, row.id);
      return update.changes === 1 ? {
        grantId: row.id,
        userId: row.user_id,
        sessionHash,
        sessionExpiresAt
      } : null;
    })();
  }
  async resolveEnrollmentSession(sessionHash, now) {
    const row = this.#database.prepare(
      `SELECT id, user_id, session_hash, session_expires_at
         FROM localwebauthn_enrollment_grants
         WHERE session_hash = ?
           AND session_expires_at > ?
           AND completed_at IS NULL
           AND revoked_at IS NULL`
    ).get(sessionHash, now);
    return row ? enrollmentSessionFromRow(row) : null;
  }
  async createChallenge(record) {
    this.#database.prepare(
      `INSERT INTO localwebauthn_challenges(
           id_hash, kind, challenge, user_id, grant_id,
           authorization_session_hash, expires_at, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      record.idHash,
      record.kind,
      record.challenge,
      record.userId,
      record.grantId,
      record.authorizationSessionHash,
      record.expiresAt,
      record.createdAt
    );
  }
  async consumeChallenge(idHash, kind, now) {
    return this.#database.transaction(() => {
      const row = this.#database.prepare(
        `SELECT kind, challenge, user_id, grant_id, authorization_session_hash
           FROM localwebauthn_challenges
           WHERE id_hash = ?
             AND kind = ?
             AND consumed_at IS NULL
             AND expires_at > ?`
      ).get(idHash, kind, now);
      if (!row) {
        return null;
      }
      const update = this.#database.prepare(
        `UPDATE localwebauthn_challenges
           SET consumed_at = ?
           WHERE id_hash = ? AND consumed_at IS NULL`
      ).run(now, idHash);
      return update.changes === 1 ? challengeFromRow(row) : null;
    })();
  }
  async listCredentials(userId, includeRevoked = false) {
    const rows = this.#database.prepare(
      `SELECT
           id, user_id, public_key, counter, transports_json, device_type,
           backed_up, label, created_at, last_used_at, revoked_at
         FROM localwebauthn_credentials
         WHERE user_id = ? AND (? = 1 OR revoked_at IS NULL)
         ORDER BY created_at, id`
    ).all(userId, includeRevoked ? 1 : 0);
    return rows.map(credentialFromRow);
  }
  async getCredential(credentialId) {
    const row = this.#database.prepare(
      `SELECT
           id, user_id, public_key, counter, transports_json, device_type,
           backed_up, label, created_at, last_used_at, revoked_at
         FROM localwebauthn_credentials
         WHERE id = ?`
    ).get(credentialId);
    return row ? credentialFromRow(row) : null;
  }
  async completeRegistration(input) {
    try {
      return this.#database.transaction(() => {
        if (!this.#registrationAuthorizationIsValid(input)) {
          return false;
        }
        const credential = input.credential;
        this.#database.prepare(
          `INSERT INTO localwebauthn_credentials(
               id, user_id, public_key, counter, transports_json,
               device_type, backed_up, label, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
          credential.id,
          credential.userId,
          credential.publicKey,
          credential.counter,
          JSON.stringify(credential.transports),
          credential.deviceType,
          credential.backedUp ? 1 : 0,
          credential.label,
          credential.createdAt
        );
        if (input.challenge.grantId) {
          const completion = this.#database.prepare(
            `UPDATE localwebauthn_enrollment_grants
               SET completed_at = ?
               WHERE id = ?
                 AND session_hash = ?
                 AND session_expires_at > ?
                 AND completed_at IS NULL
                 AND revoked_at IS NULL`
          ).run(input.now, input.challenge.grantId, input.enrollmentSessionHash, input.now);
          if (completion.changes !== 1) {
            throw new Error("Enrollment grant changed during registration.");
          }
        }
        this.#insertSession(input.session);
        return true;
      })();
    } catch {
      return false;
    }
  }
  async completeAuthentication(input) {
    try {
      return this.#database.transaction(() => {
        const update = this.#database.prepare(
          `UPDATE localwebauthn_credentials
             SET counter = ?, last_used_at = ?
             WHERE id = ? AND counter = ? AND revoked_at IS NULL`
        ).run(input.newCounter, input.now, input.credentialId, input.previousCounter);
        if (update.changes !== 1) {
          return false;
        }
        this.#insertSession(input.session);
        return true;
      })();
    } catch {
      return false;
    }
  }
  async resolveSession(idHash, now, idleExpiresBefore) {
    const row = this.#database.prepare(
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
    ).get(idHash, now, idleExpiresBefore);
    return row ? sessionFromRow(row) : null;
  }
  async touchSession(idHash, now) {
    return this.#database.prepare(
      `UPDATE localwebauthn_sessions
           SET last_seen_at = ?
           WHERE id_hash = ? AND revoked_at IS NULL AND expires_at > ?`
    ).run(now, idHash, now).changes === 1;
  }
  async revokeSession(idHash, now) {
    return this.#database.prepare(
      `UPDATE localwebauthn_sessions
           SET revoked_at = ?
           WHERE id_hash = ? AND revoked_at IS NULL`
    ).run(now, idHash).changes === 1;
  }
  async revokeCredential(userId, credentialId, now) {
    return this.#database.transaction(() => {
      const update = this.#database.prepare(
        `UPDATE localwebauthn_credentials
           SET revoked_at = ?
           WHERE id = ? AND user_id = ? AND revoked_at IS NULL`
      ).run(now, credentialId, userId);
      if (update.changes !== 1) {
        return false;
      }
      this.#database.prepare(
        `UPDATE localwebauthn_sessions
           SET revoked_at = ?
           WHERE credential_id = ? AND revoked_at IS NULL`
      ).run(now, credentialId);
      return true;
    })();
  }
  async revokeUserAuthentication(userId, now) {
    this.#database.transaction(() => {
      this.#database.prepare(
        `UPDATE localwebauthn_credentials
           SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`
      ).run(now, userId);
      this.#database.prepare(
        `UPDATE localwebauthn_sessions
           SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`
      ).run(now, userId);
      this.#database.prepare(
        `UPDATE localwebauthn_enrollment_grants
           SET revoked_at = ?
           WHERE user_id = ? AND completed_at IS NULL AND revoked_at IS NULL`
      ).run(now, userId);
      this.#database.prepare(
        `UPDATE localwebauthn_challenges
           SET consumed_at = ?
           WHERE user_id = ? AND consumed_at IS NULL`
      ).run(now, userId);
    })();
  }
  async cleanup(now) {
    return this.#database.transaction(() => ({
      enrollmentGrants: this.#database.prepare(
        `DELETE FROM localwebauthn_enrollment_grants
           WHERE (expires_at <= ? OR completed_at IS NOT NULL OR revoked_at IS NOT NULL)
             AND id NOT IN (
               SELECT grant_id FROM localwebauthn_challenges WHERE grant_id IS NOT NULL
             )`
      ).run(now).changes,
      challenges: this.#database.prepare(
        `DELETE FROM localwebauthn_challenges
           WHERE expires_at <= ? OR consumed_at IS NOT NULL`
      ).run(now).changes,
      sessions: this.#database.prepare(
        `DELETE FROM localwebauthn_sessions
           WHERE expires_at <= ? OR revoked_at IS NOT NULL`
      ).run(now).changes
    }))();
  }
  #registrationAuthorizationIsValid(input) {
    if (input.challenge.grantId && input.enrollmentSessionHash) {
      const grant = this.#database.prepare(
        `SELECT 1
           FROM localwebauthn_enrollment_grants
           WHERE id = ?
             AND user_id = ?
             AND session_hash = ?
             AND session_expires_at > ?
             AND completed_at IS NULL
             AND revoked_at IS NULL`
      ).get(
        input.challenge.grantId,
        input.credential.userId,
        input.enrollmentSessionHash,
        input.now
      );
      return Boolean(grant);
    }
    if (input.challenge.authorizationSessionHash && input.authenticatedSessionHash) {
      const session = this.#database.prepare(
        `SELECT 1
           FROM localwebauthn_sessions AS sessions
           JOIN localwebauthn_credentials AS credentials
             ON credentials.id = sessions.credential_id
           WHERE sessions.id_hash = ?
             AND sessions.user_id = ?
             AND sessions.expires_at > ?
             AND sessions.revoked_at IS NULL
             AND credentials.revoked_at IS NULL`
      ).get(input.authenticatedSessionHash, input.credential.userId, input.now);
      return Boolean(session);
    }
    return false;
  }
  #insertSession(session) {
    this.#database.prepare(
      `INSERT INTO localwebauthn_sessions(
           id_hash, user_id, credential_id, authenticated_at, expires_at, last_seen_at
         ) VALUES (?, ?, ?, ?, ?, ?)`
    ).run(
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
  SqliteLocalWebAuthnStore,
  migrateSqlite
};
