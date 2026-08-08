import {
  POSTGRES_SQL,
  SQL,
  challengeFromRow,
  credentialFromRow,
  enrollmentSessionFromRow,
  sessionFromRow,
  toPositionalPlaceholders
} from "./chunk-CSU6OHVF.js";
import {
  LOCALWEBAUTHN_SCHEMA_VERSION,
  localWebAuthnMigrationsTableStatement,
  localWebAuthnUpgradeStatements
} from "./chunk-WLETUGZ6.js";

// src/postgres.ts
var PG = Object.fromEntries(
  Object.entries(SQL).map(([name, sql]) => [name, toPositionalPlaceholders(sql)])
);
var PG_ONLY = Object.fromEntries(
  Object.entries(POSTGRES_SQL).map(([name, sql]) => [name, toPositionalPlaceholders(sql)])
);
var Rollback = class extends Error {
};
async function migratePostgres(pool, now = Date.now()) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(localWebAuthnMigrationsTableStatement("postgres"));
    const stored = await client.query(PG.selectSchemaVersion);
    const from = Number(stored.rows[0]?.version ?? 0);
    for (const statement of localWebAuthnUpgradeStatements(from, "postgres")) {
      await client.query(statement);
    }
    await client.query(PG.insertMigration, [LOCALWEBAUTHN_SCHEMA_VERSION, now]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => void 0);
    throw error;
  } finally {
    client.release();
  }
}
var PostgresLocalWebAuthnStore = class {
  #pool;
  constructor(pool) {
    this.#pool = pool;
  }
  async replaceEnrollmentGrant(record) {
    return this.#transaction(async (tx) => {
      const revoked = await tx.query(PG.revokePendingGrants, [
        record.createdAt,
        record.userId,
        record.credentialKind
      ]);
      await tx.query(PG.insertEnrollmentGrant, [
        record.id,
        record.userId,
        record.tokenHash,
        record.expiresAt,
        record.approvedByUserId,
        record.credentialKind,
        record.createdAt
      ]);
      return revoked.rows.map((row) => row.id);
    });
  }
  async revokePendingEnrollmentGrants(userId, now, credentialKind) {
    const result = await this.#pool.query(PG.revokePendingGrants, [
      now,
      userId,
      credentialKind
    ]);
    return result.rows.map((row) => row.id);
  }
  async exchangeEnrollment(tokenHash, sessionHash, sessionExpiresAt, now) {
    const result = await this.#pool.query(PG.exchangeEnrollment, [
      now,
      sessionHash,
      sessionExpiresAt,
      tokenHash,
      now
    ]);
    const row = result.rows.at(0);
    return row ? enrollmentSessionFromRow(row) : null;
  }
  async resolveEnrollmentSession(sessionHash, now) {
    const result = await this.#pool.query(PG.selectEnrollmentSession, [
      sessionHash,
      now
    ]);
    const row = result.rows.at(0);
    return row ? enrollmentSessionFromRow(row) : null;
  }
  async createChallenge(record) {
    const result = await this.#pool.query(PG.insertChallenge, [
      record.idHash,
      record.kind,
      record.challenge,
      record.userId,
      record.grantId,
      record.authorizationSessionHash,
      record.credentialKind,
      record.allowedCredentialKinds === null ? null : JSON.stringify(record.allowedCredentialKinds),
      record.expiresAt,
      record.createdAt
    ]);
    return result.rowCount === 1;
  }
  async consumeChallenge(idHash, kind, now) {
    const result = await this.#pool.query(PG.consumeChallenge, [
      now,
      idHash,
      kind,
      now
    ]);
    const row = result.rows.at(0);
    return row ? challengeFromRow(row) : null;
  }
  async listCredentials(userId, includeRevoked = false) {
    const result = await this.#pool.query(PG.selectCredentialsForUser, [
      userId,
      includeRevoked ? 1 : 0
    ]);
    return result.rows.map(credentialFromRow);
  }
  async getCredential(credentialId) {
    const result = await this.#pool.query(PG.selectCredentialById, [credentialId]);
    const row = result.rows.at(0);
    return row ? credentialFromRow(row) : null;
  }
  async credentialAncestry(userId, credentialId) {
    const result = await this.#pool.query(PG.selectCredentialAncestry, [
      credentialId,
      userId
    ]);
    return result.rows.map(credentialFromRow);
  }
  async credentialDescendants(userId, credentialId) {
    const result = await this.#pool.query(PG.selectCredentialDescendants, [
      credentialId,
      userId
    ]);
    return result.rows.map(credentialFromRow);
  }
  async completeRegistration(input) {
    try {
      return await this.#transaction(async (tx) => {
        if (!await this.#registrationIsAuthorized(tx, input)) {
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
          credential.kind,
          credential.createdVia,
          credential.parentCredentialId,
          credential.grantId,
          credential.approvedByUserId,
          credential.createdAt
        ]);
        if (input.challenge.grantId) {
          const completion = await tx.query(PG.completeEnrollmentGrant, [
            input.now,
            input.challenge.grantId,
            input.enrollmentSessionHash,
            input.now
          ]);
          if (completion.rowCount !== 1) {
            throw new Rollback();
          }
        }
        await this.#insertSession(tx, input.session);
        return true;
      });
    } catch (error) {
      if (error instanceof Rollback) {
        return false;
      }
      throw error;
    }
  }
  async completeAuthentication(input) {
    try {
      return await this.#transaction(async (tx) => {
        const advanced = await tx.query(PG.advanceCredentialCounter, [
          input.newCounter,
          input.now,
          input.credentialId,
          input.previousCounter,
          input.newCounter,
          input.newCounter
        ]);
        if (advanced.rowCount !== 1) {
          throw new Rollback();
        }
        await this.#insertSession(tx, input.session);
        return true;
      });
    } catch (error) {
      if (error instanceof Rollback) {
        return false;
      }
      throw error;
    }
  }
  async resolveSession(idHash, now, idleExpiresBefore) {
    const result = await this.#pool.query(PG.selectSession, [
      idHash,
      now,
      idleExpiresBefore
    ]);
    const row = result.rows.at(0);
    return row ? sessionFromRow(row) : null;
  }
  async touchSession(idHash, now) {
    const result = await this.#pool.query(PG.touchSession, [now, idHash, now]);
    return result.rowCount === 1;
  }
  async revokeSession(idHash, now) {
    const result = await this.#pool.query(
      PG.revokeSession,
      [now, idHash]
    );
    const row = result.rows.at(0);
    return row ? { userId: row.user_id, credentialId: row.credential_id } : null;
  }
  async revokeUserSessions(userId, now, idleExpiresBefore, exceptSessionHash) {
    const result = exceptSessionHash ? await this.#pool.query(PG.revokeLiveUserSessionsExcept, [
      now,
      userId,
      now,
      idleExpiresBefore,
      exceptSessionHash
    ]) : await this.#pool.query(PG.revokeLiveUserSessions, [now, userId, now, idleExpiresBefore]);
    return result.rowCount ?? 0;
  }
  async revokeCredential(userId, credentialId, now, options = {}) {
    return this.#transaction(async (tx) => {
      await tx.query(PG_ONLY.lockUserCredentials, [userId]);
      const allowLast = options.allowLastCredential ? 1 : 0;
      const revoked = await tx.query(PG.revokeCredential, [
        now,
        credentialId,
        userId,
        allowLast,
        userId,
        credentialId
      ]);
      if (revoked.rowCount === 1) {
        await tx.query(PG.revokeSessionsForCredential, [now, credentialId]);
        return "revoked";
      }
      if (!options.allowLastCredential) {
        const last = await tx.query(PG.isLastActiveCredential, [
          credentialId,
          userId,
          userId,
          credentialId
        ]);
        if (last.rows.length > 0) {
          return "last_credential";
        }
      }
      return "not_found";
    });
  }
  async revokeUserAuthentication(userId, now) {
    await this.#transaction(async (tx) => {
      await tx.query(PG.revokeUserCredentials, [now, userId]);
      await tx.query(PG.revokeUserSessions, [now, userId]);
      await tx.query(PG.revokeUserGrants, [now, userId]);
      await tx.query(PG.consumeUserChallenges, [now, userId]);
    });
  }
  async cleanup(now) {
    return this.#transaction(async (tx) => {
      const sessions = await tx.query(PG.deleteExpiredSessions, [now]);
      const enrollmentGrants = await tx.query(PG.deleteFinishedGrants, [now]);
      const challenges = await tx.query(PG.deleteFinishedChallenges, [now]);
      const dpopProofs = await tx.query(PG.deleteExpiredDpopProofs, [now]);
      const dpopNonces = await tx.query(PG.deleteExpiredDpopNonces, [now]);
      return {
        sessions: sessions.rowCount ?? 0,
        enrollmentGrants: enrollmentGrants.rowCount ?? 0,
        challenges: challenges.rowCount ?? 0,
        dpopProofs: dpopProofs.rowCount ?? 0,
        dpopNonces: dpopNonces.rowCount ?? 0
      };
    });
  }
  async revokeLiveCredentialSessions(credentialId, now, idleExpiresBefore, exceptSessionHash) {
    const result = exceptSessionHash ? await this.#pool.query(PG.revokeLiveCredentialSessionsExcept, [
      now,
      credentialId,
      now,
      idleExpiresBefore,
      exceptSessionHash
    ]) : await this.#pool.query(PG.revokeLiveCredentialSessions, [
      now,
      credentialId,
      now,
      idleExpiresBefore
    ]);
    return result.rowCount ?? 0;
  }
  async claimDpopProof(jtiHash, expiresAt) {
    const result = await this.#pool.query(PG.claimDpopProof, [jtiHash, expiresAt]);
    return result.rowCount === 1;
  }
  async claimDpopNonce(slot, candidate, expiresAt) {
    return this.#transaction(async (tx) => {
      await tx.query(PG.insertDpopNonce, [slot, candidate, expiresAt]);
      const result = await tx.query(PG.selectDpopNonce, [slot]);
      return result.rows[0]?.nonce ?? candidate;
    });
  }
  async dpopNonces(currentSlot, previousSlot) {
    const result = await this.#pool.query(PG.selectDpopNonces, [
      currentSlot,
      previousSlot
    ]);
    return result.rows.map((row) => row.nonce);
  }
  /** Re-check the authorizing grant or session at commit time. */
  async #registrationIsAuthorized(tx, input) {
    if (input.challenge.grantId && input.enrollmentSessionHash) {
      const result = await tx.query(PG.authorizeRegistrationByGrant, [
        input.challenge.grantId,
        input.credential.userId,
        input.enrollmentSessionHash,
        input.now
      ]);
      return result.rows.length > 0;
    }
    if (input.challenge.authorizationSessionHash && input.authenticatedSessionHash) {
      const result = await tx.query(PG.authorizeRegistrationBySession, [
        input.authenticatedSessionHash,
        input.credential.userId,
        input.now
      ]);
      return result.rows.length > 0;
    }
    return false;
  }
  async #insertSession(tx, session) {
    await tx.query(PG.insertSession, [
      session.idHash,
      session.userId,
      session.credentialId,
      session.authenticatedAt,
      session.expiresAt,
      session.lastSeenAt
    ]);
  }
  async #transaction(operation) {
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      const result = await operation(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => void 0);
      throw error;
    } finally {
      client.release();
    }
  }
};
export {
  PostgresLocalWebAuthnStore,
  migratePostgres
};
