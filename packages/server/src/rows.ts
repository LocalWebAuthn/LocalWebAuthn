import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';

import type {
  ConsumedChallenge,
  Credential,
  EnrollmentGrantRejection,
  EnrollmentGrantState,
  EnrollmentSession,
  SessionIdentity,
} from './types.js';

/**
 * Numeric columns arrive as a JavaScript `number` from SQLite and D1, but as a
 * decimal `string` from node-postgres, which returns `BIGINT` that way to avoid
 * silent precision loss. Row types therefore accept both and the mappers
 * normalize with {@link toNumber}.
 */
type NumericColumn = number | string;

/** SQLite and D1 store booleans as `0`/`1`; PostgreSQL uses a real `BOOLEAN`. */
type BooleanColumn = number | boolean;

export type CredentialRow = {
  id: string;
  user_id: string;
  public_key: unknown;
  counter: NumericColumn;
  transports_json: string;
  device_type: 'singleDevice' | 'multiDevice';
  backed_up: BooleanColumn;
  label: string;
  kind: string | null;
  created_via: string | null;
  parent_credential_id: string | null;
  grant_id: string | null;
  approved_by_user_id: string | null;
  created_at: NumericColumn;
  last_used_at: NumericColumn | null;
  revoked_at: NumericColumn | null;
};

export type ChallengeRow = {
  kind: 'registration' | 'authentication';
  challenge: string;
  user_id: string | null;
  grant_id: string | null;
  authorization_session_hash: unknown;
  credential_kind: string | null;
  allowed_credential_kinds: string | null;
  registration_generation: number | string | null;
};

export type EnrollmentSessionRow = {
  id: string;
  user_id: string;
  session_hash: unknown;
  session_expires_at: NumericColumn;
  credential_kind: string | null;
  approved_by_user_id: string | null;
};

export type EnrollmentGrantStateRow = {
  user_id: string;
  token_consumed_at: NumericColumn | null;
  completed_at: NumericColumn | null;
  revoked_at: NumericColumn | null;
  expires_at: NumericColumn;
};

export type SessionRow = {
  user_id: string;
  credential_id: string;
  authenticated_at: NumericColumn;
  expires_at: NumericColumn;
  last_seen_at: NumericColumn;
  /** From the joined credential, not the session row itself. */
  kind: string | null;
};

/**
 * Coerce a numeric column to a `number`, rejecting values that cannot round-trip.
 *
 * Every timestamp this package stores is milliseconds since the epoch and every
 * counter is a WebAuthn `uint32`, so both sit far inside the safe-integer range.
 * A value outside it means the column holds something unexpected, and silently
 * truncating it could corrupt an expiry comparison or a counter check.
 */
export function toNumber(value: NumericColumn): number {
  const numeric = typeof value === 'string' ? Number(value) : value;
  if (!Number.isSafeInteger(numeric)) {
    throw new TypeError(`Expected a safe integer database value, received ${String(value)}.`);
  }
  return numeric;
}

function toNullableNumber(value: NumericColumn | null): number | null {
  return value === null ? null : toNumber(value);
}

export function toBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) {
    return new Uint8Array(value);
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (Array.isArray(value) && value.every((entry) => Number.isInteger(entry))) {
    return Uint8Array.from(value);
  }
  throw new TypeError('Expected a database BLOB value.');
}

function parseTransports(value: string): AuthenticatorTransportFuture[] {
  const parsed: unknown = JSON.parse(value);
  const isTransport = (transport: unknown): transport is AuthenticatorTransportFuture =>
    typeof transport === 'string';
  return Array.isArray(parsed) && parsed.every(isTransport) ? parsed : [];
}

export function credentialFromRow(row: CredentialRow): Credential {
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
    createdVia:
      row.created_via === 'enrollment' || row.created_via === 'credential' ? row.created_via : null,
    parentCredentialId: row.parent_credential_id,
    grantId: row.grant_id,
    approvedByUserId: row.approved_by_user_id,
    createdAt: toNumber(row.created_at),
    lastUsedAt: toNullableNumber(row.last_used_at),
    revokedAt: toNullableNumber(row.revoked_at),
  };
}

/**
 * Parse the JSON array of admissible credential kinds.
 *
 * `null` means "unconstrained". A stored value that does not parse to an array
 * of strings-or-null is treated as an empty set, which admits nothing — failing
 * closed, because this column gates which credentials may authenticate.
 */
function parseAllowedKinds(value: string | null): (string | null)[] | null {
  if (value === null) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return [];
  }
  const isKind = (kind: unknown): kind is string | null =>
    typeof kind === 'string' || kind === null;
  return Array.isArray(parsed) && parsed.every(isKind) ? parsed : [];
}

export function challengeFromRow(row: ChallengeRow): ConsumedChallenge {
  return {
    kind: row.kind,
    challenge: row.challenge,
    userId: row.user_id,
    grantId: row.grant_id,
    authorizationSessionHash:
      row.authorization_session_hash === null ? null : toBytes(row.authorization_session_hash),
    credentialKind: row.credential_kind,
    allowedCredentialKinds: parseAllowedKinds(row.allowed_credential_kinds),
    // PostgreSQL returns BIGINT as a string; normalize like every other counter.
    registrationGeneration:
      row.registration_generation === null ? null : toNumber(row.registration_generation),
  };
}

export function enrollmentSessionFromRow(row: EnrollmentSessionRow): EnrollmentSession {
  return {
    grantId: row.id,
    userId: row.user_id,
    sessionHash: toBytes(row.session_hash),
    sessionExpiresAt: toNumber(row.session_expires_at),
    credentialKind: row.credential_kind,
    approvedByUserId: row.approved_by_user_id,
  };
}

/**
 * Classify a refused enrollment token from its grant row.
 *
 * Order is the whole content of this function. A row can be several of these at
 * once — a token consumed at 10:00 whose grant expired at 10:30 is both used and
 * expired — and the host's message must key on the most informative fact, not the
 * most recent one. "Used" wins over everything, because it is the only state that
 * can mean somebody else got there first. Revocation outranks expiry for the
 * opposite reason: it is the benign explanation and must not be reported as an
 * alarm.
 *
 * Absent rows are the caller's business; this is only reached with a row in hand.
 */
export function enrollmentGrantStateFromRow(
  row: EnrollmentGrantStateRow,
  now: number,
): EnrollmentGrantRejection {
  return { state: grantState(row, now), userId: row.user_id };
}

function grantState(row: EnrollmentGrantStateRow, now: number): EnrollmentGrantState {
  if (row.token_consumed_at !== null || row.completed_at !== null) {
    return 'used';
  }
  if (row.revoked_at !== null) {
    return 'superseded';
  }
  if (toNumber(row.expires_at) <= now) {
    return 'expired';
  }
  // A live, unspent, unrevoked grant that `exchangeEnrollment` still refused. The
  // only way here is a race — another request consumed it between the two
  // statements — so it was used, just not yet when this row was read.
  return 'used';
}

export function sessionFromRow(row: SessionRow): SessionIdentity {
  return {
    userId: row.user_id,
    credentialId: row.credential_id,
    authenticatedAt: toNumber(row.authenticated_at),
    expiresAt: toNumber(row.expires_at),
    lastSeenAt: toNumber(row.last_seen_at),
    credentialKind: row.kind,
  };
}
