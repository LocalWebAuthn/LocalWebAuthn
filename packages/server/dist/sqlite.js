import {
  ORPHANED_CREDENTIAL_GRACE_MS,
  SQL,
  challengeFromRow,
  credentialFromRow,
  enrollmentSessionFromRow,
  sessionFromRow
} from "./chunk-IFRZR4MT.js";
import {
  LOCALWEBAUTHN_SCHEMA_SQL,
  LOCALWEBAUTHN_SCHEMA_VERSION
} from "./chunk-6NWV3XTI.js";

// src/sqlite.ts
function migrateSqlite(database, now = Date.now()) {
  database.transaction(() => {
    database.exec(LOCALWEBAUTHN_SCHEMA_SQL);
    database.prepare(SQL.insertMigration).run(LOCALWEBAUTHN_SCHEMA_VERSION, now);
  })();
}
var SqliteLocalWebAuthnStore = class {
  #database;
  constructor(database) {
    this.#database = database;
  }
  async replaceEnrollmentGrant(record) {
    return this.#database.transaction(() => {
      const revoked = this.#database.prepare(SQL.revokePendingGrants).all(record.createdAt, record.userId);
      this.#database.prepare(SQL.insertEnrollmentGrant).run(
        record.id,
        record.userId,
        record.tokenHash,
        record.expiresAt,
        record.approvedByUserId,
        record.createdAt
      );
      return revoked.map((row) => row.id);
    })();
  }
  async exchangeEnrollment(tokenHash, sessionHash, sessionExpiresAt, now) {
    const row = this.#database.prepare(SQL.exchangeEnrollment).get(now, sessionHash, sessionExpiresAt, tokenHash, now);
    return row ? enrollmentSessionFromRow(row) : null;
  }
  async resolveEnrollmentSession(sessionHash, now) {
    const row = this.#database.prepare(SQL.selectEnrollmentSession).get(sessionHash, now);
    return row ? enrollmentSessionFromRow(row) : null;
  }
  async createChallenge(record) {
    return this.#database.prepare(SQL.insertChallenge).run(
      record.idHash,
      record.kind,
      record.challenge,
      record.userId,
      record.grantId,
      record.authorizationSessionHash,
      record.expiresAt,
      record.createdAt
    ).changes === 1;
  }
  async consumeChallenge(idHash, kind, now) {
    const row = this.#database.prepare(SQL.consumeChallenge).get(now, idHash, kind, now);
    return row ? challengeFromRow(row) : null;
  }
  async listCredentials(userId, includeRevoked = false) {
    const rows = this.#database.prepare(SQL.selectCredentialsForUser).all(userId, includeRevoked ? 1 : 0);
    return rows.map(credentialFromRow);
  }
  async getCredential(credentialId) {
    const row = this.#database.prepare(SQL.selectCredentialById).get(credentialId);
    return row ? credentialFromRow(row) : null;
  }
  async completeRegistration(input) {
    try {
      return this.#database.transaction(() => {
        if (!this.#registrationIsAuthorized(input)) {
          return false;
        }
        const credential = input.credential;
        this.#database.prepare(SQL.insertCredential).run(
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
          const completion = this.#database.prepare(SQL.completeEnrollmentGrant).run(input.now, input.challenge.grantId, input.enrollmentSessionHash, input.now);
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
        const advanced = this.#database.prepare(SQL.advanceCredentialCounter).run(input.newCounter, input.now, input.credentialId, input.previousCounter);
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
  async resolveSession(idHash, now, idleExpiresBefore) {
    const row = this.#database.prepare(SQL.selectSession).get(idHash, now, idleExpiresBefore);
    return row ? sessionFromRow(row) : null;
  }
  async touchSession(idHash, now) {
    return this.#database.prepare(SQL.touchSession).run(now, idHash, now).changes === 1;
  }
  async revokeSession(idHash, now) {
    return this.#database.prepare(SQL.revokeSession).run(now, idHash).changes === 1;
  }
  async revokeCredential(userId, credentialId, now) {
    return this.#database.transaction(() => {
      const revoked = this.#database.prepare(SQL.revokeCredential).run(now, credentialId, userId);
      if (revoked.changes !== 1) {
        return false;
      }
      this.#database.prepare(SQL.revokeSessionsForCredential).run(now, credentialId);
      return true;
    })();
  }
  async revokeUserAuthentication(userId, now) {
    this.#database.transaction(() => {
      this.#database.prepare(SQL.revokeUserCredentials).run(now, userId);
      this.#database.prepare(SQL.revokeUserSessions).run(now, userId);
      this.#database.prepare(SQL.revokeUserGrants).run(now, userId);
      this.#database.prepare(SQL.consumeUserChallenges).run(now, userId);
    })();
  }
  async cleanup(now) {
    return this.#database.transaction(() => {
      const sessions = this.#database.prepare(SQL.deleteExpiredSessions).run(now).changes;
      const orphanedCredentials = this.#database.prepare(SQL.deleteOrphanedCredentials).run(now - ORPHANED_CREDENTIAL_GRACE_MS).changes;
      const enrollmentGrants = this.#database.prepare(SQL.deleteFinishedGrants).run(now).changes;
      const challenges = this.#database.prepare(SQL.deleteFinishedChallenges).run(now).changes;
      return { enrollmentGrants, challenges, sessions, orphanedCredentials };
    })();
  }
  /** Re-check the authorizing grant or session at commit time. */
  #registrationIsAuthorized(input) {
    if (input.challenge.grantId && input.enrollmentSessionHash) {
      return Boolean(
        this.#database.prepare(SQL.authorizeRegistrationByGrant).get(
          input.challenge.grantId,
          input.credential.userId,
          input.enrollmentSessionHash,
          input.now
        )
      );
    }
    if (input.challenge.authorizationSessionHash && input.authenticatedSessionHash) {
      return Boolean(
        this.#database.prepare(SQL.authorizeRegistrationBySession).get(input.authenticatedSessionHash, input.credential.userId, input.now)
      );
    }
    return false;
  }
  #insertSession(session) {
    this.#database.prepare(SQL.insertSession).run(
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
