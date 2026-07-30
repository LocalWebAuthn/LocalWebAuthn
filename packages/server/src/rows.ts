import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';

import type { ConsumedChallenge, Credential, EnrollmentSession, SessionIdentity } from './types.js';

export type CredentialRow = {
  id: string;
  user_id: string;
  public_key: unknown;
  counter: number;
  transports_json: string;
  device_type: 'singleDevice' | 'multiDevice';
  backed_up: number;
  label: string;
  created_at: number;
  last_used_at: number | null;
  revoked_at: number | null;
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
  session_expires_at: number;
};

export type SessionRow = {
  user_id: string;
  credential_id: string;
  authenticated_at: number;
  expires_at: number;
  last_seen_at: number;
};

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
    counter: row.counter,
    transports: parseTransports(row.transports_json),
    deviceType: row.device_type,
    backedUp: row.backed_up === 1,
    label: row.label,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
    revokedAt: row.revoked_at,
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
    sessionExpiresAt: row.session_expires_at,
  };
}

export function sessionFromRow(row: SessionRow): SessionIdentity {
  return {
    userId: row.user_id,
    credentialId: row.credential_id,
    authenticatedAt: row.authenticated_at,
    expiresAt: row.expires_at,
    lastSeenAt: row.last_seen_at,
  };
}
