import {
  SQL,
  challengeFromRow,
  credentialFromRow,
  enrollmentGrantStateFromRow,
  enrollmentSessionFromRow,
  sessionFromRow
} from "./chunk-OVMYNLID.js";
import {
  LOCALWEBAUTHN_SCHEMA_VERSION,
  localWebAuthnMigrationsTableStatement,
  localWebAuthnUpgradeStatements
} from "./chunk-U6SG3F4P.js";

// src/sqlite.ts
var Rollback = class extends Error {
};
function migrateSqlite(database, now = Date.now()) {
  database.exec("PRAGMA foreign_keys = ON");
  database.transaction(() => {
    database.exec(localWebAuthnMigrationsTableStatement("sqlite"));
    const stored = database.prepare(SQL.selectSchemaVersion).get();
    const from = stored?.version ?? 0;
    for (const statement of localWebAuthnUpgradeStatements(from, "sqlite")) {
      database.exec(statement);
    }
    database.prepare(SQL.insertMigration).run(LOCALWEBAUTHN_SCHEMA_VERSION, now);
  }).immediate();
}
var SqliteLocalWebAuthnStore = class {
  #database;
  constructor(database) {
    this.#database = database;
    database.exec("PRAGMA foreign_keys = ON");
  }
  async replaceEnrollmentGrant(record) {
    return this.#database.transaction(() => {
      const revoked = this.#database.prepare(SQL.revokePendingGrants).all(record.createdAt, record.userId, record.credentialKind);
      this.#database.prepare(SQL.insertEnrollmentGrant).run(
        record.id,
        record.userId,
        record.tokenHash,
        record.expiresAt,
        record.approvedByUserId,
        record.credentialKind,
        record.createdAt
      );
      return revoked.map((row) => row.id);
    }).immediate();
  }
  async revokePendingEnrollmentGrants(userId, now, credentialKind) {
    const rows = this.#database.prepare(SQL.revokePendingGrants).all(now, userId, credentialKind);
    return rows.map((row) => row.id);
  }
  async exchangeEnrollment(tokenHash, sessionHash, sessionExpiresAt, now) {
    const row = this.#database.prepare(SQL.exchangeEnrollment).get(now, sessionHash, sessionExpiresAt, tokenHash, now);
    return row ? enrollmentSessionFromRow(row) : null;
  }
  async enrollmentGrantState(tokenHash, now) {
    const row = this.#database.prepare(SQL.selectEnrollmentGrantState).get(tokenHash);
    return row ? enrollmentGrantStateFromRow(row, now) : { state: "unknown", userId: null };
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
      record.credentialKind,
      record.allowedCredentialKinds === null ? null : JSON.stringify(record.allowedCredentialKinds),
      record.registrationGeneration,
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
  async credentialAncestry(userId, credentialId) {
    const rows = this.#database.prepare(SQL.selectCredentialAncestry).all(credentialId, userId);
    return rows.map(credentialFromRow);
  }
  async credentialDescendants(userId, credentialId) {
    const rows = this.#database.prepare(SQL.selectCredentialDescendants).all(credentialId, userId);
    return rows.map(credentialFromRow);
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
          credential.kind,
          credential.createdVia,
          credential.parentCredentialId,
          credential.grantId,
          credential.approvedByUserId,
          credential.createdAt
        );
        if (input.challenge.grantId) {
          const completion = this.#database.prepare(SQL.completeEnrollmentGrant).run(input.now, input.challenge.grantId, input.enrollmentSessionHash, input.now);
          if (completion.changes !== 1) {
            throw new Rollback();
          }
        }
        this.#insertSession(input.session);
        return true;
      }).immediate();
    } catch (error) {
      if (error instanceof Rollback) {
        return false;
      }
      throw error;
    }
  }
  async completeAuthentication(input) {
    return this.#database.transaction(() => {
      const advanced = this.#database.prepare(SQL.advanceCredentialCounter).run(
        input.newCounter,
        input.now,
        input.credentialId,
        input.previousCounter,
        input.newCounter,
        input.newCounter
      );
      if (advanced.changes !== 1) {
        return false;
      }
      this.#insertSession(input.session);
      return true;
    }).immediate();
  }
  async resolveSession(idHash, now, idleExpiresBefore) {
    const row = this.#database.prepare(SQL.selectSession).get(idHash, now, idleExpiresBefore);
    return row ? sessionFromRow(row) : null;
  }
  async touchSession(idHash, now) {
    return this.#database.prepare(SQL.touchSession).run(now, idHash, now).changes === 1;
  }
  async revokeSession(idHash, now) {
    const row = this.#database.prepare(SQL.revokeSession).get(now, idHash);
    return row ? { userId: row.user_id, credentialId: row.credential_id } : null;
  }
  async revokeUserSessions(userId, now, idleExpiresBefore, exceptSessionHash) {
    if (exceptSessionHash) {
      return this.#database.prepare(SQL.revokeLiveUserSessionsExcept).run(now, userId, now, idleExpiresBefore, exceptSessionHash).changes;
    }
    return this.#database.prepare(SQL.revokeLiveUserSessions).run(now, userId, now, idleExpiresBefore).changes;
  }
  async revokeLiveCredentialSessions(credentialId, now, idleExpiresBefore, exceptSessionHash) {
    return exceptSessionHash ? this.#database.prepare(SQL.revokeLiveCredentialSessionsExcept).run(now, credentialId, now, idleExpiresBefore, exceptSessionHash).changes : this.#database.prepare(SQL.revokeLiveCredentialSessions).run(now, credentialId, now, idleExpiresBefore).changes;
  }
  async revokeCredential(userId, credentialId, now, options = {}) {
    return this.#database.transaction(() => {
      const allowLast = options.allowLastCredential ? 1 : 0;
      const revoked = this.#database.prepare(SQL.revokeCredential).run(now, credentialId, userId, allowLast, userId, credentialId);
      if (revoked.changes === 1) {
        this.#database.prepare(SQL.revokeSessionsForCredential).run(now, credentialId);
        return "revoked";
      }
      if (!options.allowLastCredential && this.#database.prepare(SQL.isLastActiveCredential).get(credentialId, userId, userId, credentialId)) {
        return "last_credential";
      }
      return "not_found";
    }).immediate();
  }
  async revokeUserAuthentication(userId, now) {
    this.#database.transaction(() => {
      this.#database.prepare(SQL.revokeUserCredentials).run(now, userId);
      this.#database.prepare(SQL.revokeUserSessions).run(now, userId);
      this.#database.prepare(SQL.revokeUserGrants).run(now, userId);
      this.#database.prepare(SQL.consumeUserChallenges).run(now, userId);
    }).immediate();
  }
  async claimDpopProof(jtiHash, expiresAt) {
    return this.#database.prepare(SQL.claimDpopProof).run(jtiHash, expiresAt).changes === 1;
  }
  async claimDpopNonce(slot, candidate, expiresAt) {
    return this.#database.transaction(() => {
      this.#database.prepare(SQL.insertDpopNonce).run(slot, candidate, expiresAt);
      const row = this.#database.prepare(SQL.selectDpopNonce).get(slot);
      return row?.nonce ?? candidate;
    }).immediate();
  }
  async dpopNonces(currentSlot, previousSlot) {
    const rows = this.#database.prepare(SQL.selectDpopNonces).all(currentSlot, previousSlot);
    return rows.map((row) => row.nonce);
  }
  async cleanup(now) {
    return this.#database.transaction(() => {
      const sessions = this.#database.prepare(SQL.deleteExpiredSessions).run(now).changes;
      const enrollmentGrants = this.#database.prepare(SQL.deleteFinishedGrants).run(now).changes;
      const challenges = this.#database.prepare(SQL.deleteFinishedChallenges).run(now).changes;
      const dpopProofs = this.#database.prepare(SQL.deleteExpiredDpopProofs).run(now).changes;
      const dpopNonces = this.#database.prepare(SQL.deleteExpiredDpopNonces).run(now).changes;
      return { enrollmentGrants, challenges, sessions, dpopProofs, dpopNonces };
    }).immediate();
  }
  /** Re-check the authorizing grant or session at commit time. */
  #registrationIsAuthorized(input) {
    if (!this.#fenceHolds(input)) {
      return false;
    }
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
  /** Whether the challenge's recorded generation is still the current one. */
  #fenceHolds(input) {
    const expected = input.challenge.registrationGeneration;
    if (expected === null) {
      return true;
    }
    const row = this.#database.prepare(SQL.selectRegistrationFence).get(input.credential.userId);
    return (row?.generation ?? 0) === expected;
  }
  async registrationGeneration(userId, now) {
    this.#database.prepare(SQL.ensureRegistrationFence).run(userId, now);
    const row = this.#database.prepare(SQL.selectRegistrationFence).get(userId);
    return row?.generation ?? 0;
  }
  async bumpRegistrationGeneration(userId, now) {
    const row = this.#database.prepare(SQL.bumpRegistrationFence).get(userId, now);
    return row.generation;
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
