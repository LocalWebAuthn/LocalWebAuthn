/**
 * Canonical SQL for every LocalWebAuthn store operation.
 *
 * All three official adapters (SQLite, Cloudflare D1, PostgreSQL) execute these
 * exact statements, so each query has one definition to audit rather than one
 * per adapter. The statements use only syntax common to modern SQLite and
 * PostgreSQL: `ON CONFLICT DO NOTHING`, `RETURNING`, and plain sub-selects.
 *
 * Placeholders are written as `?`. PostgreSQL requires `$1`-style placeholders;
 * {@link toPositionalPlaceholders} rewrites them once at module load.
 *
 * The `RETURNING` clauses require SQLite 3.35 or newer (March 2021), which is
 * comfortably older than any SQLite bundled with better-sqlite3 11+ or served
 * by D1.
 *
 * Adapters differ in how they achieve atomicity, not in what they execute:
 * SQLite and PostgreSQL wrap multi-statement operations in a transaction, while
 * D1 — which cannot open one — guards each step on the preceding statement's
 * row count. That difference lives in the adapters; the SQL lives here.
 */
export const SQL = {
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

  /**
   * Revoke every live session for a user, leaving credentials and grants
   * untouched. "Live" mirrors selectSession's predicates (not revoked, not past
   * absolute expiry, not idle-expired), so the row count reports sessions that
   * could still have resolved — not stale rows awaiting cleanup.
   *
   * Binds: now, userId, now, idleExpiresBefore.
   */
  revokeLiveUserSessions: `
    UPDATE localwebauthn_sessions
    SET revoked_at = ?
    WHERE user_id = ?
      AND revoked_at IS NULL
      AND expires_at > ?
      AND last_seen_at > ?`,

  /**
   * As {@link SQL.revokeLiveUserSessions}, sparing one session — the caller's
   * own, for "sign out everywhere else".
   *
   * Binds: now, userId, now, idleExpiresBefore, exceptIdHash.
   */
  revokeLiveUserSessionsExcept: `
    UPDATE localwebauthn_sessions
    SET revoked_at = ?
    WHERE user_id = ?
      AND revoked_at IS NULL
      AND expires_at > ?
      AND last_seen_at > ?
      AND id_hash <> ?`,

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
    ON CONFLICT DO NOTHING`,
} as const;

/**
 * SQL used only by the D1 adapter.
 *
 * D1 cannot open a transaction, so it cannot check authorization and insert the
 * credential as two statements — another request could invalidate the grant in
 * between. These statements fold the check into the insert: `WHERE EXISTS`
 * makes the insert affect zero rows unless the authorization still holds, and
 * the adapter's row-count guard turns that into a failed batch.
 *
 * There is one statement per authorization path. The caller already knows which
 * path it is on, so neither statement carries the other's parameters.
 */
export const D1_SQL = {
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

  clearGuard: `DELETE FROM localwebauthn_transaction_guard`,
} as const;

/**
 * SQL used only by the PostgreSQL adapter.
 *
 * SQLite and D1 serialize writers, so a conditional `UPDATE` whose predicate
 * counts the user's other active credentials is atomic there. PostgreSQL is
 * MVCC: under the default READ COMMITTED isolation, an `EXISTS` sub-select does
 * not block on another transaction's uncommitted `UPDATE` of a *different* row.
 * Two concurrent revokes of two different credentials would therefore each see
 * the other as still active and both succeed, emptying the account.
 */
export const POSTGRES_SQL = {
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
    FOR UPDATE`,
} as const;

/**
 * Rewrite `?` placeholders as PostgreSQL's `$1`, `$2`, … positional form.
 *
 * Safe for these statements because none of them contain a `?` inside a string
 * literal; `queries.test.ts` asserts that remains true.
 */
export function toPositionalPlaceholders(sql: string): string {
  let index = 0;
  return sql.replace(/\?/gu, () => `$${String(++index)}`);
}
