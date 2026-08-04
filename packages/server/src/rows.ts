import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';

import type { ConsumedChallenge, Credential, EnrollmentSession, SessionIdentity } from './types.js';

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
};

export type EnrollmentSessionRow = {
  id: string;
  user_id: string;
  session_hash: unknown;
  session_expires_at: NumericColumn;
};

export type SessionRow = {
  user_id: string;
  credential_id: string;
  authenticated_at: NumericColumn;
  expires_at: NumericColumn;
  last_seen_at: NumericColumn;
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
    createdAt: toNumber(row.created_at),
    lastUsedAt: toNullableNumber(row.last_used_at),
    revokedAt: toNullableNumber(row.revoked_at),
  };
}

export function challengeFromRow(row: ChallengeRow): ConsumedChallenge {
  return {
    kind: row.kind,
    challenge: row.challenge,
    userId: row.user_id,
    grantId: row.grant_id,
    authorizationSessionHash:
      row.authorization_session_hash === null ? null : toBytes(row.authorization_session_hash),
  };
}

export function enrollmentSessionFromRow(row: EnrollmentSessionRow): EnrollmentSession {
  return {
    grantId: row.id,
    userId: row.user_id,
    sessionHash: toBytes(row.session_hash),
    sessionExpiresAt: toNumber(row.session_expires_at),
  };
}

export function sessionFromRow(row: SessionRow): SessionIdentity {
  return {
    userId: row.user_id,
    credentialId: row.credential_id,
    authenticatedAt: toNumber(row.authenticated_at),
    expiresAt: toNumber(row.expires_at),
    lastSeenAt: toNumber(row.last_seen_at),
  };
}
