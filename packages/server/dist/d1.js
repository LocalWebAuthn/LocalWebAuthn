import {
  D1_GUARD_COLUMN,
  D1_SQL,
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

// src/d1.ts
async function migrateD1(database, now = Date.now()) {
  await database.prepare(localWebAuthnMigrationsTableStatement()).run();
  const from = await installedD1Version(database);
  const upgrade = localWebAuthnUpgradeStatements(from, "sqlite");
  if (upgrade.length === 0) {
    return;
  }
  try {
    await database.batch([
      ...upgrade.map((statement) => database.prepare(statement)),
      database.prepare(SQL.insertMigration).bind(LOCALWEBAUTHN_SCHEMA_VERSION, now)
    ]);
  } catch (error) {
    if (await installedD1Version(database) >= LOCALWEBAUTHN_SCHEMA_VERSION) {
      return;
    }
    throw error;
  }
}
async function installedD1Version(database) {
  const row = await database.prepare(SQL.selectSchemaVersion).first();
  return row?.version ?? 0;
}
function errorText(error) {
  if (typeof error === "string") {
    return error;
  }
  if (!(error instanceof Error)) {
    return "";
  }
  const cause = error.cause;
  const causeText = cause instanceof Error ? cause.message : typeof cause === "string" ? cause : "";
  return causeText ? `${error.message}
${causeText}` : error.message;
}
function isD1TransactionGuardFailure(error) {
  return errorText(error).includes(`NOT NULL constraint failed: ${D1_GUARD_COLUMN}`);
}
function guardTripped(error) {
  if (isD1TransactionGuardFailure(error)) {
    return false;
  }
  throw error;
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
    const revoked = await this.#database.prepare(SQL.revokePendingGrants).bind(record.createdAt, record.userId, record.credentialKind).run();
    await this.#database.prepare(SQL.insertEnrollmentGrant).bind(
      record.id,
      record.userId,
      record.tokenHash,
      record.expiresAt,
      record.approvedByUserId,
      record.credentialKind,
      record.createdAt
    ).run();
    return revoked.results.map((row) => row.id);
  }
  async revokePendingEnrollmentGrants(userId, now, credentialKind) {
    const result = await this.#database.prepare(SQL.revokePendingGrants).bind(now, userId, credentialKind).all();
    return result.results.map((row) => row.id);
  }
  async exchangeEnrollment(tokenHash, sessionHash, sessionExpiresAt, now) {
    const row = await returningRow(
      this.#database.prepare(SQL.exchangeEnrollment).bind(now, sessionHash, sessionExpiresAt, tokenHash, now)
    );
    return row ? enrollmentSessionFromRow(row) : null;
  }
  async enrollmentGrantState(tokenHash, now) {
    const row = await this.#database.prepare(SQL.selectEnrollmentGrantState).bind(tokenHash).first();
    return row ? enrollmentGrantStateFromRow(row, now) : { state: "unknown", userId: null };
  }
  async resolveEnrollmentSession(sessionHash, now) {
    const row = await this.#database.prepare(SQL.selectEnrollmentSession).bind(sessionHash, now).first();
    return row ? enrollmentSessionFromRow(row) : null;
  }
  async createChallenge(record) {
    const result = await this.#database.prepare(SQL.insertChallenge).bind(
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
    ).run();
    return changes(result) === 1;
  }
  async consumeChallenge(idHash, kind, now) {
    const row = await returningRow(
      this.#database.prepare(SQL.consumeChallenge).bind(now, idHash, kind, now)
    );
    return row ? challengeFromRow(row) : null;
  }
  async listCredentials(userId, includeRevoked = false) {
    const result = await this.#database.prepare(SQL.selectCredentialsForUser).bind(userId, includeRevoked ? 1 : 0).all();
    return result.results.map(credentialFromRow);
  }
  async getCredential(credentialId) {
    const row = await this.#database.prepare(SQL.selectCredentialById).bind(credentialId).first();
    return row ? credentialFromRow(row) : null;
  }
  async credentialAncestry(userId, credentialId) {
    const result = await this.#database.prepare(SQL.selectCredentialAncestry).bind(credentialId, userId).all();
    return result.results.map(credentialFromRow);
  }
  async credentialDescendants(userId, credentialId) {
    const result = await this.#database.prepare(SQL.selectCredentialDescendants).bind(credentialId, userId).all();
    return result.results.map(credentialFromRow);
  }
  async completeRegistration(input) {
    const { credential, challenge, enrollmentSessionHash, authenticatedSessionHash, session, now } = input;
    const grantId = challenge.grantId;
    let credentialInsert;
    if (grantId && enrollmentSessionHash) {
      credentialInsert = this.#database.prepare(D1_SQL.insertCredentialIfGrantValid).bind(
        ...this.#credentialValues(credential),
        grantId,
        credential.userId,
        enrollmentSessionHash,
        now
      );
    } else if (challenge.authorizationSessionHash && authenticatedSessionHash) {
      credentialInsert = this.#database.prepare(D1_SQL.insertCredentialIfSessionValid).bind(
        ...this.#credentialValues(credential),
        authenticatedSessionHash,
        credential.userId,
        now
      );
    } else {
      return false;
    }
    const statements = challenge.registrationGeneration === null ? [credentialInsert, this.#guard()] : [
      this.#database.prepare(D1_SQL.guardRegistrationFence).bind(credential.userId, challenge.registrationGeneration),
      credentialInsert,
      this.#guard()
    ];
    if (grantId) {
      statements.push(
        this.#database.prepare(SQL.completeEnrollmentGrant).bind(now, grantId, enrollmentSessionHash, now),
        this.#guard()
      );
    }
    statements.push(
      this.#insertSessionStatement(session),
      this.#guard(),
      this.#database.prepare(D1_SQL.clearGuard)
    );
    try {
      await this.#database.batch(statements);
      return true;
    } catch (error) {
      return guardTripped(error);
    }
  }
  async completeAuthentication(input) {
    try {
      await this.#database.batch([
        this.#database.prepare(SQL.advanceCredentialCounter).bind(
          input.newCounter,
          input.now,
          input.credentialId,
          input.previousCounter,
          input.newCounter,
          input.newCounter
        ),
        this.#guard(),
        this.#insertSessionStatement(input.session),
        this.#guard(),
        this.#database.prepare(D1_SQL.clearGuard)
      ]);
      return true;
    } catch (error) {
      return guardTripped(error);
    }
  }
  async resolveSession(idHash, now, idleExpiresBefore) {
    const row = await this.#database.prepare(SQL.selectSession).bind(idHash, now, idleExpiresBefore).first();
    return row ? sessionFromRow(row) : null;
  }
  async touchSession(idHash, now) {
    const result = await this.#database.prepare(SQL.touchSession).bind(now, idHash, now).run();
    return changes(result) === 1;
  }
  async revokeSession(idHash, now) {
    const row = await returningRow(
      this.#database.prepare(SQL.revokeSession).bind(now, idHash)
    );
    return row ? { userId: row.user_id, credentialId: row.credential_id } : null;
  }
  async revokeUserSessions(userId, now, idleExpiresBefore, exceptSessionHash) {
    const statement = exceptSessionHash ? this.#database.prepare(SQL.revokeLiveUserSessionsExcept).bind(now, userId, now, idleExpiresBefore, exceptSessionHash) : this.#database.prepare(SQL.revokeLiveUserSessions).bind(now, userId, now, idleExpiresBefore);
    return changes(await statement.run());
  }
  async revokeCredential(userId, credentialId, now, options = {}) {
    const allowLast = options.allowLastCredential ? 1 : 0;
    const results = await this.#database.batch([
      this.#database.prepare(SQL.revokeCredential).bind(now, credentialId, userId, allowLast, userId, credentialId),
      this.#database.prepare(SQL.revokeSessionsForCredential).bind(now, credentialId)
    ]);
    if (changes(results[0]) === 1) {
      return "revoked";
    }
    if (!options.allowLastCredential) {
      const last = await this.#database.prepare(SQL.isLastActiveCredential).bind(credentialId, userId, userId, credentialId).first();
      if (last) {
        return "last_credential";
      }
    }
    return "not_found";
  }
  async revokeUserAuthentication(userId, now) {
    await this.#database.batch([
      this.#database.prepare(SQL.revokeUserCredentials).bind(now, userId),
      this.#database.prepare(SQL.revokeUserSessions).bind(now, userId),
      this.#database.prepare(SQL.revokeUserGrants).bind(now, userId),
      this.#database.prepare(SQL.consumeUserChallenges).bind(now, userId)
    ]);
  }
  async cleanup(now) {
    const results = await this.#database.batch([
      this.#database.prepare(SQL.deleteExpiredSessions).bind(now),
      this.#database.prepare(SQL.deleteFinishedGrants).bind(now),
      this.#database.prepare(SQL.deleteFinishedChallenges).bind(now),
      this.#database.prepare(SQL.deleteExpiredDpopProofs).bind(now),
      this.#database.prepare(SQL.deleteExpiredDpopNonces).bind(now)
    ]);
    return {
      sessions: changes(results[0]),
      enrollmentGrants: changes(results[1]),
      challenges: changes(results[2]),
      dpopProofs: changes(results[3]),
      dpopNonces: changes(results[4])
    };
  }
  async registrationGeneration(userId, now) {
    await this.#database.prepare(SQL.ensureRegistrationFence).bind(userId, now).run();
    const row = await this.#database.prepare(SQL.selectRegistrationFence).bind(userId).first();
    return row?.generation ?? 0;
  }
  async bumpRegistrationGeneration(userId, now) {
    const row = await this.#database.prepare(SQL.bumpRegistrationFence).bind(userId, now).first();
    return row?.generation ?? 0;
  }
  async claimDpopProof(jtiHash, expiresAt) {
    const result = await this.#database.prepare(SQL.claimDpopProof).bind(jtiHash, expiresAt).run();
    return changes(result) === 1;
  }
  async revokeLiveCredentialSessions(credentialId, now, idleExpiresBefore, exceptSessionHash) {
    const statement = exceptSessionHash ? this.#database.prepare(SQL.revokeLiveCredentialSessionsExcept).bind(now, credentialId, now, idleExpiresBefore, exceptSessionHash) : this.#database.prepare(SQL.revokeLiveCredentialSessions).bind(now, credentialId, now, idleExpiresBefore);
    return changes(await statement.run());
  }
  async claimDpopNonce(slot, candidate, expiresAt) {
    await this.#database.prepare(SQL.insertDpopNonce).bind(slot, candidate, expiresAt).run();
    const row = await this.#database.prepare(SQL.selectDpopNonce).bind(slot).first();
    return row?.nonce ?? candidate;
  }
  async dpopNonces(currentSlot, previousSlot) {
    const result = await this.#database.prepare(SQL.selectDpopNonces).bind(currentSlot, previousSlot).all();
    return result.results.map((row) => row.nonce);
  }
  /** The ten `localwebauthn_credentials` column values, in schema order. */
  #credentialValues(credential) {
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
      credential.createdAt
    ];
  }
  #guard() {
    return this.#database.prepare(D1_SQL.guardPreviousChange);
  }
  #insertSessionStatement(session) {
    return this.#database.prepare(SQL.insertSession).bind(
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
  isD1TransactionGuardFailure,
  migrateD1
};
