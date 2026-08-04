// src/queries.ts
var SQL = {
  // -- Enrollment grants ----------------------------------------------------
  /** Revoke every pending grant for a user, returning the revoked IDs. */
  revokePendingGrants: `
    UPDATE localwebauthn_enrollment_grants
    SET revoked_at = ?
    WHERE user_id = ? AND completed_at IS NULL AND revoked_at IS NULL
    RETURNING id`,
  insertEnrollmentGrant: `
    INSERT INTO localwebauthn_enrollment_grants(
      id, user_id, token_hash, expires_at, approved_by_user_id, created_at
    ) VALUES (?, ?, ?, ?, ?, ?)`,
  /**
   * Consume an enrollment token and open an enrollment session in one atomic
   * statement. Returns no rows when the token is unknown, already consumed,
   * expired, completed, or revoked.
   */
  exchangeEnrollment: `
    UPDATE localwebauthn_enrollment_grants
    SET token_consumed_at = ?, session_hash = ?, session_expires_at = ?
    WHERE token_hash = ?
      AND token_consumed_at IS NULL
      AND completed_at IS NULL
      AND revoked_at IS NULL
      AND expires_at > ?
    RETURNING id, user_id, session_hash, session_expires_at`,
  selectEnrollmentSession: `
    SELECT id, user_id, session_hash, session_expires_at
    FROM localwebauthn_enrollment_grants
    WHERE session_hash = ?
      AND session_expires_at > ?
      AND completed_at IS NULL
      AND revoked_at IS NULL`,
  completeEnrollmentGrant: `
    UPDATE localwebauthn_enrollment_grants
    SET completed_at = ?
    WHERE id = ?
      AND session_hash = ?
      AND session_expires_at > ?
      AND completed_at IS NULL
      AND revoked_at IS NULL`,
  // -- Challenges -----------------------------------------------------------
  /** `ON CONFLICT DO NOTHING` makes a duplicate `id_hash` report zero rows. */
  insertChallenge: `
    INSERT INTO localwebauthn_challenges(
      id_hash, kind, challenge, user_id, grant_id,
      authorization_session_hash, expires_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT DO NOTHING`,
  /** Consume a challenge exactly once; returns no rows on replay or expiry. */
  consumeChallenge: `
    UPDATE localwebauthn_challenges
    SET consumed_at = ?
    WHERE id_hash = ?
      AND kind = ?
      AND consumed_at IS NULL
      AND expires_at > ?
    RETURNING kind, challenge, user_id, grant_id, authorization_session_hash`,
  // -- Credentials ----------------------------------------------------------
  selectCredentialsForUser: `
    SELECT
      id, user_id, public_key, counter, transports_json, device_type,
      backed_up, label, created_at, last_used_at, revoked_at
    FROM localwebauthn_credentials
    WHERE user_id = ? AND (? = 1 OR revoked_at IS NULL)
    ORDER BY created_at, id`,
  selectCredentialById: `
    SELECT
      id, user_id, public_key, counter, transports_json, device_type,
      backed_up, label, created_at, last_used_at, revoked_at
    FROM localwebauthn_credentials
    WHERE id = ?`,
  insertCredential: `
    INSERT INTO localwebauthn_credentials(
      id, user_id, public_key, counter, transports_json,
      device_type, backed_up, label, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  /**
   * Compare-and-swap the signature counter.
   *
   * Zero rows means replay, concurrent auth, revocation, or a non-increasing
   * non-zero counter. WebAuthn allows 0→0 (authenticators without counters);
   * any other non-increase is rejected here as defense in depth.
   *
   * Binds: newCounter, now, credentialId, previousCounter, newCounter, newCounter.
   */
  advanceCredentialCounter: `
    UPDATE localwebauthn_credentials
    SET counter = ?, last_used_at = ?
    WHERE id = ?
      AND counter = ?
      AND revoked_at IS NULL
      AND (? > counter OR (counter = 0 AND ? = 0))`,
  /**
   * Revoke one credential. When `allow_last` is 0, the row is updated only if
   * another active credential for the same user still exists — so the last
   * active passkey cannot be removed without an explicit recovery override.
   *
   * Binds: now, credentialId, userId, allowLast (1 or 0), userId, credentialId.
   */
  revokeCredential: `
    UPDATE localwebauthn_credentials
    SET revoked_at = ?
    WHERE id = ?
      AND user_id = ?
      AND revoked_at IS NULL
      AND (
        ? = 1
        OR EXISTS (
          SELECT 1
          FROM localwebauthn_credentials AS other
          WHERE other.user_id = ?
            AND other.id <> ?
            AND other.revoked_at IS NULL
        )
      )`,
  /** True when the credential is active and is the user's only active passkey. */
  isLastActiveCredential: `
    SELECT 1 AS ok
    FROM localwebauthn_credentials
    WHERE id = ?
      AND user_id = ?
      AND revoked_at IS NULL
      AND NOT EXISTS (
        SELECT 1
        FROM localwebauthn_credentials AS other
        WHERE other.user_id = ?
          AND other.id <> ?
          AND other.revoked_at IS NULL
      )`,
  revokeUserCredentials: `
    UPDATE localwebauthn_credentials
    SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
  // -- Registration authorization ------------------------------------------
  //
  // A registration is authorized by exactly one of two things: an exchanged
  // enrollment grant, or an already-authenticated session adding another
  // passkey. Each path has its own query so neither carries the other's
  // parameters.
  /** Grant path: the enrollment grant is still open and matches the session. */
  authorizeRegistrationByGrant: `
    SELECT 1 AS ok
    FROM localwebauthn_enrollment_grants
    WHERE id = ?
      AND user_id = ?
      AND session_hash = ?
      AND session_expires_at > ?
      AND completed_at IS NULL
      AND revoked_at IS NULL`,
  /** Session path: the authenticated session and its credential are live. */
  authorizeRegistrationBySession: `
    SELECT 1 AS ok
    FROM localwebauthn_sessions AS sessions
    JOIN localwebauthn_credentials AS credentials
      ON credentials.id = sessions.credential_id
    WHERE sessions.id_hash = ?
      AND sessions.user_id = ?
      AND sessions.expires_at > ?
      AND sessions.revoked_at IS NULL
      AND credentials.revoked_at IS NULL`,
  // -- Sessions -------------------------------------------------------------
  insertSession: `
    INSERT INTO localwebauthn_sessions(
      id_hash, user_id, credential_id, authenticated_at, expires_at, last_seen_at
    ) VALUES (?, ?, ?, ?, ?, ?)`,
  selectSession: `
    SELECT
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
  touchSession: `
    UPDATE localwebauthn_sessions
    SET last_seen_at = ?
    WHERE id_hash = ? AND revoked_at IS NULL AND expires_at > ?`,
  /** Revoke a session and return its identity for audit events. */
  revokeSession: `
    UPDATE localwebauthn_sessions
    SET revoked_at = ?
    WHERE id_hash = ? AND revoked_at IS NULL
    RETURNING user_id, credential_id`,
  revokeSessionsForCredential: `
    UPDATE localwebauthn_sessions
    SET revoked_at = ?
    WHERE credential_id = ? AND revoked_at IS NULL`,
  revokeUserSessions: `
    UPDATE localwebauthn_sessions
    SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
  // -- User-wide revocation -------------------------------------------------
  revokeUserGrants: `
    UPDATE localwebauthn_enrollment_grants
    SET revoked_at = ?
    WHERE user_id = ? AND completed_at IS NULL AND revoked_at IS NULL`,
  consumeUserChallenges: `
    UPDATE localwebauthn_challenges
    SET consumed_at = ?
    WHERE user_id = ? AND consumed_at IS NULL`,
  // -- Cleanup --------------------------------------------------------------
  //
  // Ephemeral rows only. Credentials are never listed here.
  deleteExpiredSessions: `
    DELETE FROM localwebauthn_sessions
    WHERE expires_at <= ? OR revoked_at IS NOT NULL`,
  deleteFinishedGrants: `
    DELETE FROM localwebauthn_enrollment_grants
    WHERE (expires_at <= ? OR completed_at IS NOT NULL OR revoked_at IS NOT NULL)
      AND id NOT IN (
        SELECT grant_id FROM localwebauthn_challenges WHERE grant_id IS NOT NULL
      )`,
  deleteFinishedChallenges: `
    DELETE FROM localwebauthn_challenges
    WHERE expires_at <= ? OR consumed_at IS NOT NULL`,
  // -- Migrations -----------------------------------------------------------
  insertMigration: `
    INSERT INTO localwebauthn_migrations(version, applied_at)
    VALUES (?, ?)
    ON CONFLICT DO NOTHING`
};
var D1_SQL = {
  /** Grant path: 9 credential columns, then grant id, user id, session hash, now. */
  insertCredentialIfGrantValid: `
    INSERT INTO localwebauthn_credentials(
      id, user_id, public_key, counter, transports_json,
      device_type, backed_up, label, created_at
    )
    SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
    WHERE EXISTS (
      SELECT 1 FROM localwebauthn_enrollment_grants
      WHERE id = ?
        AND user_id = ?
        AND session_hash = ?
        AND session_expires_at > ?
        AND completed_at IS NULL
        AND revoked_at IS NULL
    )`,
  /** Session path: 9 credential columns, then session hash, user id, now. */
  insertCredentialIfSessionValid: `
    INSERT INTO localwebauthn_credentials(
      id, user_id, public_key, counter, transports_json,
      device_type, backed_up, label, created_at
    )
    SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
    WHERE EXISTS (
      SELECT 1
      FROM localwebauthn_sessions AS sessions
      JOIN localwebauthn_credentials AS credentials
        ON credentials.id = sessions.credential_id
      WHERE sessions.id_hash = ?
        AND sessions.user_id = ?
        AND sessions.expires_at > ?
        AND sessions.revoked_at IS NULL
        AND credentials.revoked_at IS NULL
    )`,
  /**
   * Fails the surrounding batch unless the preceding statement changed exactly
   * one row, because `localwebauthn_transaction_guard.value` is `CHECK (value = 1)`.
   */
  guardPreviousChange: `INSERT INTO localwebauthn_transaction_guard(value) VALUES (changes())`,
  clearGuard: `DELETE FROM localwebauthn_transaction_guard`
};
var POSTGRES_SQL = {
  /**
   * Take a row lock on the user's active credentials before evaluating the
   * last-credential predicate. The second concurrent revoke blocks here until
   * the first commits, then sees the true remaining set.
   *
   * `ORDER BY id` makes the lock acquisition order deterministic so two
   * transactions locking the same user cannot deadlock against each other.
   */
  lockUserCredentials: `
    SELECT id FROM localwebauthn_credentials
    WHERE user_id = ? AND revoked_at IS NULL
    ORDER BY id
    FOR UPDATE`
};
function toPositionalPlaceholders(sql) {
  let index = 0;
  return sql.replace(/\?/gu, () => `$${String(++index)}`);
}

// src/rows.ts
function toNumber(value) {
  const numeric = typeof value === "string" ? Number(value) : value;
  if (!Number.isSafeInteger(numeric)) {
    throw new TypeError(`Expected a safe integer database value, received ${String(value)}.`);
  }
  return numeric;
}
function toNullableNumber(value) {
  return value === null ? null : toNumber(value);
}
function toBytes(value) {
  if (value instanceof Uint8Array) {
    return new Uint8Array(value);
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (Array.isArray(value) && value.every((entry) => Number.isInteger(entry))) {
    return Uint8Array.from(value);
  }
  throw new TypeError("Expected a database BLOB value.");
}
function parseTransports(value) {
  const parsed = JSON.parse(value);
  const isTransport = (transport) => typeof transport === "string";
  return Array.isArray(parsed) && parsed.every(isTransport) ? parsed : [];
}
function credentialFromRow(row) {
  return {
    id: row.id,
    userId: row.user_id,
    publicKey: toBytes(row.public_key),
    counter: toNumber(row.counter),
    transports: parseTransports(row.transports_json),
    deviceType: row.device_type,
    backedUp: row.backed_up === 1 || row.backed_up === true,
    label: row.label,
    createdAt: toNumber(row.created_at),
    lastUsedAt: toNullableNumber(row.last_used_at),
    revokedAt: toNullableNumber(row.revoked_at)
  };
}
function challengeFromRow(row) {
  return {
    kind: row.kind,
    challenge: row.challenge,
    userId: row.user_id,
    grantId: row.grant_id,
    authorizationSessionHash: row.authorization_session_hash === null ? null : toBytes(row.authorization_session_hash)
  };
}
function enrollmentSessionFromRow(row) {
  return {
    grantId: row.id,
    userId: row.user_id,
    sessionHash: toBytes(row.session_hash),
    sessionExpiresAt: toNumber(row.session_expires_at)
  };
}
function sessionFromRow(row) {
  return {
    userId: row.user_id,
    credentialId: row.credential_id,
    authenticatedAt: toNumber(row.authenticated_at),
    expiresAt: toNumber(row.expires_at),
    lastSeenAt: toNumber(row.last_seen_at)
  };
}

export {
  SQL,
  D1_SQL,
  POSTGRES_SQL,
  toPositionalPlaceholders,
  credentialFromRow,
  challengeFromRow,
  enrollmentSessionFromRow,
  sessionFromRow
};
