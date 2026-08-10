// src/queries.ts
var SQL = {
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
    RETURNING id, user_id, session_hash, session_expires_at, credential_kind,
              approved_by_user_id`,
  selectEnrollmentSession: `
    SELECT id, user_id, session_hash, session_expires_at, credential_kind,
           approved_by_user_id
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
      registration_generation, expires_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
              credential_kind, allowed_credential_kinds, registration_generation`,
  // -- Credentials ----------------------------------------------------------
  selectCredentialsForUser: `
    SELECT
      id, user_id, public_key, counter, transports_json, device_type,
      backed_up, label, kind, created_via, parent_credential_id, grant_id,
      approved_by_user_id, created_at, last_used_at, revoked_at
    FROM localwebauthn_credentials
    WHERE user_id = ? AND (? = 1 OR revoked_at IS NULL)
    ORDER BY created_at, id`,
  selectCredentialById: `
    SELECT
      id, user_id, public_key, counter, transports_json, device_type,
      backed_up, label, kind, created_via, parent_credential_id, grant_id,
      approved_by_user_id, created_at, last_used_at, revoked_at
    FROM localwebauthn_credentials
    WHERE id = ?`,
  insertCredential: `
    INSERT INTO localwebauthn_credentials(
      id, user_id, public_key, counter, transports_json,
      device_type, backed_up, label, kind, created_via,
      parent_credential_id, grant_id, approved_by_user_id, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  // -- Credential heritage --------------------------------------------------
  //
  // Every credential this package creates was authorized either by an enrollment
  // grant or by an existing credential's session, and both are known at
  // registration. Recording them makes the chain queryable afterwards, which the
  // ephemeral rows never allowed: consumed challenges are reaped on the next
  // cleanup and completed grants on the one after, so the linkage used to vanish
  // within minutes.
  //
  // `WITH RECURSIVE` is available in SQLite 3.8.3+ and PostgreSQL, so these run
  // unchanged on all three adapters.
  //
  // The `depth < 64` guard cannot trigger on well-formed data: a credential can
  // only be created by one that already exists, so the graph is acyclic by
  // construction. It is there because an unbounded recursive query is a hang, and
  // a hang is a worse failure than a truncated answer.
  /**
   * A credential and its ancestors, root first.
   *
   * Binds: credentialId, userId. Depth counts upward from the subject, so the
   * `ORDER BY` reverses it to put the root -- the credential that came from an
   * enrollment grant -- at the top.
   */
  selectCredentialAncestry: `
    WITH RECURSIVE localwebauthn_ancestry(id, depth) AS (
      SELECT id, 0 FROM localwebauthn_credentials WHERE id = ? AND user_id = ?
      UNION ALL
      SELECT credentials.parent_credential_id, localwebauthn_ancestry.depth + 1
      FROM localwebauthn_credentials AS credentials
      JOIN localwebauthn_ancestry ON credentials.id = localwebauthn_ancestry.id
      WHERE credentials.parent_credential_id IS NOT NULL AND localwebauthn_ancestry.depth < 64
    )
    SELECT
      id, user_id, public_key, counter, transports_json, device_type,
      backed_up, label, kind, created_via, parent_credential_id, grant_id,
      approved_by_user_id, created_at, last_used_at, revoked_at
    FROM localwebauthn_ancestry
    JOIN localwebauthn_credentials USING (id)
    ORDER BY localwebauthn_ancestry.depth DESC`,
  /**
   * A credential and everything descended from it, nearest first.
   *
   * Depth 0 is the credential itself, so this is the exact set the tree revoke
   * acts on.
   *
   * Binds: credentialId, userId.
   */
  selectCredentialDescendants: `
    WITH RECURSIVE localwebauthn_descendants(id, depth) AS (
      SELECT id, 0 FROM localwebauthn_credentials WHERE id = ? AND user_id = ?
      UNION ALL
      SELECT credentials.id, localwebauthn_descendants.depth + 1
      FROM localwebauthn_credentials AS credentials
      JOIN localwebauthn_descendants
        ON credentials.parent_credential_id = localwebauthn_descendants.id
      WHERE localwebauthn_descendants.depth < 64
    )
    SELECT
      id, user_id, public_key, counter, transports_json, device_type,
      backed_up, label, kind, created_via, parent_credential_id, grant_id,
      approved_by_user_id, created_at, last_used_at, revoked_at
    FROM localwebauthn_descendants
    JOIN localwebauthn_credentials USING (id)
    ORDER BY localwebauthn_descendants.depth, id`,
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
  // -- Registration fence ---------------------------------------------------
  /**
   * The user's current registration generation, or no row before their first
   * registration (read as generation 0).
   *
   * Read inside the same transaction that commits a credential: it is the
   * optimistic-concurrency version that says "no revocation has happened since
   * this challenge was issued". PostgreSQL takes `FOR UPDATE` on it as well —
   * see `POSTGRES_SQL.lockRegistrationFence` — because a predicate over
   * credentials cannot stop a *phantom* insert, while a shared row can.
   */
  selectRegistrationFence: `
    SELECT generation FROM localwebauthn_registration_fences WHERE user_id = ?`,
  /** Create the user's fence row at generation 0 if they have none yet. */
  ensureRegistrationFence: `
    INSERT INTO localwebauthn_registration_fences(user_id, generation, updated_at)
    VALUES (?, 0, ?)
    ON CONFLICT DO NOTHING`,
  /**
   * Advance the generation, invalidating every challenge issued under the old
   * one. Every revocation path calls this, which is what makes a revoke able to
   * cancel registrations that are already in flight.
   */
  bumpRegistrationFence: `
    INSERT INTO localwebauthn_registration_fences(user_id, generation, updated_at)
    VALUES (?, 1, ?)
    ON CONFLICT(user_id) DO UPDATE
      SET generation = localwebauthn_registration_fences.generation + 1,
          updated_at = excluded.updated_at
    RETURNING generation`,
  // -- Migrations -----------------------------------------------------------
  /** Highest applied schema version, or no rows on a fresh database. */
  selectSchemaVersion: `
    SELECT MAX(version) AS version FROM localwebauthn_migrations`,
  insertMigration: `
    INSERT INTO localwebauthn_migrations(version, applied_at)
    VALUES (?, ?)
    ON CONFLICT DO NOTHING`
};
var D1_GUARD_COLUMN = "localwebauthn_transaction_guard.value";
var D1_SQL = {
  /** Grant path: 14 credential columns, then grant id, user id, session hash, now. */
  insertCredentialIfGrantValid: `
    INSERT INTO localwebauthn_credentials(
      id, user_id, public_key, counter, transports_json,
      device_type, backed_up, label, kind, created_via,
      parent_credential_id, grant_id, approved_by_user_id, created_at
    )
    SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    WHERE EXISTS (
      SELECT 1 FROM localwebauthn_enrollment_grants
      WHERE id = ?
        AND user_id = ?
        AND session_hash = ?
        AND session_expires_at > ?
        AND completed_at IS NULL
        AND revoked_at IS NULL
    )`,
  /** Session path: 14 credential columns, then session hash, user id, now. */
  insertCredentialIfSessionValid: `
    INSERT INTO localwebauthn_credentials(
      id, user_id, public_key, counter, transports_json,
      device_type, backed_up, label, kind, created_via,
      parent_credential_id, grant_id, approved_by_user_id, created_at
    )
    SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
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
   * one row.
   *
   * It fails by inserting `NULL` into a `NOT NULL` column, which is deliberate and
   * is the whole reason this reads oddly. D1 surfaces no error codes — only a
   * message string — so the *only* way {@link isD1TransactionGuardFailure} can tell
   * "the guard tripped" from "the database is broken" is by what that message names.
   * A `NOT NULL` violation names the column:
   *
   *     NOT NULL constraint failed: localwebauthn_transaction_guard.value
   *
   * which is {@link D1_GUARD_COLUMN} — a name this package owns. The obvious
   * alternative, letting the table's `CHECK (value = 1)` fail, reports only its own
   * expression (`CHECK constraint failed: value = 1`) and names neither the table
   * nor anything else unique to us, so it cannot be told apart from an unrelated
   * `CHECK` on some other table.
   */
  guardPreviousChange: `
    INSERT INTO localwebauthn_transaction_guard(value)
    SELECT CASE WHEN changes() = 1 THEN 1 ELSE NULL END`,
  /**
   * Fails the surrounding batch unless the user's registration generation still
   * equals the one recorded on the challenge — the registration fence, failing the
   * same way {@link guardPreviousChange} does: it inserts `1` when the fence holds
   * and `NULL` (which violates `NOT NULL`, rolling the batch back under a name we
   * own) when a revoke has moved it.
   *
   * Binds: user id, expected generation.
   */
  guardRegistrationFence: `
    INSERT INTO localwebauthn_transaction_guard(value)
    SELECT CASE
      WHEN COALESCE((
        SELECT generation FROM localwebauthn_registration_fences WHERE user_id = ?
      ), 0) = ? THEN 1
      ELSE NULL
    END`,
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
    FOR UPDATE`,
  /**
   * Lock the user's registration fence while committing a credential, so a
   * concurrent revoke serializes against it.
   *
   * This is the row that makes the fence work on PostgreSQL, and the reason the
   * fence is a table rather than a predicate over `credentials`. Remediation
   * revokes with `UPDATE … WHERE revoked_at IS NULL`; a registration committing
   * concurrently inserts a row that update has already scanned past — a phantom
   * READ COMMITTED cannot prevent, and no lock on existing credential rows can
   * either, because the row does not exist yet. Both paths touching one shared
   * fence row gives them something real to conflict on: the revoke blocks here
   * until the registration commits (and then revokes it), or the registration
   * blocks and then fails its generation check.
   */
  lockRegistrationFence: `
    SELECT generation FROM localwebauthn_registration_fences
    WHERE user_id = ?
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
    kind: row.kind,
    createdVia: row.created_via === "enrollment" || row.created_via === "credential" ? row.created_via : null,
    parentCredentialId: row.parent_credential_id,
    grantId: row.grant_id,
    approvedByUserId: row.approved_by_user_id,
    createdAt: toNumber(row.created_at),
    lastUsedAt: toNullableNumber(row.last_used_at),
    revokedAt: toNullableNumber(row.revoked_at)
  };
}
function parseAllowedKinds(value) {
  if (value === null) {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    return [];
  }
  const isKind = (kind) => typeof kind === "string" || kind === null;
  return Array.isArray(parsed) && parsed.every(isKind) ? parsed : [];
}
function challengeFromRow(row) {
  return {
    kind: row.kind,
    challenge: row.challenge,
    userId: row.user_id,
    grantId: row.grant_id,
    authorizationSessionHash: row.authorization_session_hash === null ? null : toBytes(row.authorization_session_hash),
    credentialKind: row.credential_kind,
    allowedCredentialKinds: parseAllowedKinds(row.allowed_credential_kinds),
    // PostgreSQL returns BIGINT as a string; normalize like every other counter.
    registrationGeneration: row.registration_generation === null ? null : toNumber(row.registration_generation)
  };
}
function enrollmentSessionFromRow(row) {
  return {
    grantId: row.id,
    userId: row.user_id,
    sessionHash: toBytes(row.session_hash),
    sessionExpiresAt: toNumber(row.session_expires_at),
    credentialKind: row.credential_kind,
    approvedByUserId: row.approved_by_user_id
  };
}
function sessionFromRow(row) {
  return {
    userId: row.user_id,
    credentialId: row.credential_id,
    authenticatedAt: toNumber(row.authenticated_at),
    expiresAt: toNumber(row.expires_at),
    lastSeenAt: toNumber(row.last_seen_at),
    credentialKind: row.kind
  };
}

export {
  SQL,
  D1_GUARD_COLUMN,
  D1_SQL,
  POSTGRES_SQL,
  toPositionalPlaceholders,
  credentialFromRow,
  challengeFromRow,
  enrollmentSessionFromRow,
  sessionFromRow
};
