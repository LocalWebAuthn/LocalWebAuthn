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

  /**
   * Revoke every pending grant for a user *of one kind*, returning the revoked IDs.
   *
   * Kind-scoped so issuing a deployment-key grant does not silently cancel a
   * person's in-flight enrollment link. `COALESCE` because `NULL <> NULL`: every
   * grant from a host that ignores kinds is `NULL` and must still form one group.
   *
   * Binds: now, userId, credentialKind.
   */
  revokePendingGrants: `
    UPDATE localwebauthn_enrollment_grants
    SET revoked_at = ?
    WHERE user_id = ?
      AND COALESCE(credential_kind, '') = COALESCE(?, '')
      AND completed_at IS NULL
      AND revoked_at IS NULL
    RETURNING id`,

  insertEnrollmentGrant: `
    INSERT INTO localwebauthn_enrollment_grants(
      id, user_id, token_hash, expires_at, approved_by_user_id, credential_kind, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)`,

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
    RETURNING id, user_id, session_hash, session_expires_at, credential_kind`,

  selectEnrollmentSession: `
    SELECT id, user_id, session_hash, session_expires_at, credential_kind
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
      authorization_session_hash, credential_kind, allowed_credential_kinds,
      expires_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT DO NOTHING`,

  /** Consume a challenge exactly once; returns no rows on replay or expiry. */
  consumeChallenge: `
    UPDATE localwebauthn_challenges
    SET consumed_at = ?
    WHERE id_hash = ?
      AND kind = ?
      AND consumed_at IS NULL
      AND expires_at > ?
    RETURNING kind, challenge, user_id, grant_id, authorization_session_hash,
              credential_kind, allowed_credential_kinds`,

  // -- Credentials ----------------------------------------------------------

  selectCredentialsForUser: `
    SELECT
      id, user_id, public_key, counter, transports_json, device_type,
      backed_up, label, kind, created_at, last_used_at, revoked_at
    FROM localwebauthn_credentials
    WHERE user_id = ? AND (? = 1 OR revoked_at IS NULL)
    ORDER BY created_at, id`,

  selectCredentialById: `
    SELECT
      id, user_id, public_key, counter, transports_json, device_type,
      backed_up, label, kind, created_at, last_used_at, revoked_at
    FROM localwebauthn_credentials
    WHERE id = ?`,

  insertCredential: `
    INSERT INTO localwebauthn_credentials(
      id, user_id, public_key, counter, transports_json,
      device_type, backed_up, label, kind, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,

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
   * another active credential *of the same kind* for the same user still exists
   * — so the last active passkey of a kind cannot be removed without an
   * explicit recovery override.
   *
   * Scoping the guard by kind is what stops a deployment key from counting as
   * the human's fallback: without it, a person holding one passkey and one API
   * credential could have their only passkey revoked and be told it worked.
   * `COALESCE` is required because `NULL <> NULL` — every pre-`kind` credential
   * is kind `NULL` and must still count as one group. For any user whose
   * credentials share a kind (including all-`NULL`), this is exactly the old
   * behaviour.
   *
   * Binds: now, credentialId, userId, allowLast (1 or 0), userId, credentialId.
   */
  revokeCredential: `
    UPDATE localwebauthn_credentials AS target
    SET revoked_at = ?
    WHERE target.id = ?
      AND target.user_id = ?
      AND target.revoked_at IS NULL
      AND (
        ? = 1
        OR EXISTS (
          SELECT 1
          FROM localwebauthn_credentials AS other
          WHERE other.user_id = ?
            AND other.id <> ?
            AND other.revoked_at IS NULL
            AND COALESCE(other.kind, '') = COALESCE(target.kind, '')
        )
      )`,

  /** True when the credential is active and is the user's only active passkey of its kind. */
  isLastActiveCredential: `
    SELECT 1 AS ok
    FROM localwebauthn_credentials AS target
    WHERE target.id = ?
      AND target.user_id = ?
      AND target.revoked_at IS NULL
      AND NOT EXISTS (
        SELECT 1
        FROM localwebauthn_credentials AS other
        WHERE other.user_id = ?
          AND other.id <> ?
          AND other.revoked_at IS NULL
          AND COALESCE(other.kind, '') = COALESCE(target.kind, '')
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

  /**
   * The credential join already exists to enforce "credential not revoked", so
   * carrying `credentials.kind` out of it costs nothing and lets
   * {@link LocalWebAuthn.resolveSession} report the kind without a second query.
   */
  selectSession: `
    SELECT
      sessions.user_id, sessions.credential_id, sessions.authenticated_at,
      sessions.expires_at, sessions.last_seen_at, credentials.kind
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

  /**
   * As {@link SQL.revokeLiveUserSessions}, for one credential.
   *
   * A kind-filtered bulk revoke loops this rather than binding a variable-length
   * `IN (...)` list, which the shared static SQL cannot express and which would
   * otherwise have to be built per call. Revocation is an administrative
   * operation, so a statement per credential is the better trade than dynamic SQL
   * that no longer lives in this module.
   *
   * Binds: now, credentialId, now, idleExpiresBefore.
   */
  revokeLiveCredentialSessions: `
    UPDATE localwebauthn_sessions
    SET revoked_at = ?
    WHERE credential_id = ?
      AND revoked_at IS NULL
      AND expires_at > ?
      AND last_seen_at > ?`,

  /**
   * As above, sparing one session.
   *
   * Binds: now, credentialId, now, idleExpiresBefore, exceptIdHash.
   */
  revokeLiveCredentialSessionsExcept: `
    UPDATE localwebauthn_sessions
    SET revoked_at = ?
    WHERE credential_id = ?
      AND revoked_at IS NULL
      AND expires_at > ?
      AND last_seen_at > ?
      AND id_hash <> ?`,

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

  deleteExpiredDpopProofs: `
    DELETE FROM localwebauthn_dpop_proofs WHERE expires_at <= ?`,

  // -- DPoP proof replay cache ----------------------------------------------

  /**
   * Claim a proof's `jti` exactly once. `ON CONFLICT DO NOTHING` makes a replay
   * report zero rows, which is the whole mechanism: the first request carrying a
   * given `jti` wins and every repeat is refused.
   *
   * The raw `jti` is never stored — only its digest, for the same reason
   * challenge and session tokens are stored hashed.
   */
  claimDpopProof: `
    INSERT INTO localwebauthn_dpop_proofs(jti_hash, expires_at)
    VALUES (?, ?)
    ON CONFLICT DO NOTHING`,

  // -- DPoP nonces ----------------------------------------------------------
  //
  // A nonce is the server's contribution of unpredictability to a per-request
  // proof: everything else in one — `jti`, `iat`, `htm`, `htu`, the key — is
  // chosen by the client. It stops a key holder pre-generating proofs, because
  // it cannot sign for a value the server has not issued yet.
  //
  // Keyed by time slot rather than held in a mutable "current nonce" row, which
  // matters for a multi-server deployment: a rotate-in-place row is a
  // read-modify-write and two servers can lose each other's update. Here the
  // primary key does the coordinating — whichever server inserts a slot first
  // wins, and every other server reads that same value back.
  //
  // Nonces are stored in the clear, unlike every other token in this schema.
  // They are not secrets: the server hands the current one to any caller that
  // asks, in a response header. The property is only that a *future* one cannot
  // be guessed.

  /** Claim a slot's nonce; a loser's insert is a no-op and it reads the winner's. */
  insertDpopNonce: `
    INSERT INTO localwebauthn_dpop_nonces(slot, nonce, expires_at)
    VALUES (?, ?, ?)
    ON CONFLICT DO NOTHING`,

  selectDpopNonce: `
    SELECT nonce FROM localwebauthn_dpop_nonces WHERE slot = ?`,

  /** Current and previous slot, so rotation does not reject an in-flight request. */
  selectDpopNonces: `
    SELECT nonce FROM localwebauthn_dpop_nonces WHERE slot = ? OR slot = ?`,

  deleteExpiredDpopNonces: `
    DELETE FROM localwebauthn_dpop_nonces WHERE expires_at <= ?`,

  // -- Migrations -----------------------------------------------------------

  createMigrationsTable: `
    CREATE TABLE IF NOT EXISTS localwebauthn_migrations (
      version INTEGER PRIMARY KEY,
      applied_at INTEGER NOT NULL
    )`,

  /** Highest applied schema version, or no rows on a fresh database. */
  selectSchemaVersion: `
    SELECT MAX(version) AS version FROM localwebauthn_migrations`,

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
  /** Grant path: 10 credential columns, then grant id, user id, session hash, now. */
  insertCredentialIfGrantValid: `
    INSERT INTO localwebauthn_credentials(
      id, user_id, public_key, counter, transports_json,
      device_type, backed_up, label, kind, created_at
    )
    SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    WHERE EXISTS (
      SELECT 1 FROM localwebauthn_enrollment_grants
      WHERE id = ?
        AND user_id = ?
        AND session_hash = ?
        AND session_expires_at > ?
        AND completed_at IS NULL
        AND revoked_at IS NULL
    )`,

  /** Session path: 10 credential columns, then session hash, user id, now. */
  insertCredentialIfSessionValid: `
    INSERT INTO localwebauthn_credentials(
      id, user_id, public_key, counter, transports_json,
      device_type, backed_up, label, kind, created_at
    )
    SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
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
