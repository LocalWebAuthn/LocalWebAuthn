// src/rows.ts
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
    counter: row.counter,
    transports: parseTransports(row.transports_json),
    deviceType: row.device_type,
    backedUp: row.backed_up === 1,
    label: row.label,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
    revokedAt: row.revoked_at
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
    sessionExpiresAt: row.session_expires_at
  };
}
function sessionFromRow(row) {
  return {
    userId: row.user_id,
    credentialId: row.credential_id,
    authenticatedAt: row.authenticated_at,
    expiresAt: row.expires_at,
    lastSeenAt: row.last_seen_at
  };
}

export {
  credentialFromRow,
  challengeFromRow,
  enrollmentSessionFromRow,
  sessionFromRow
};
