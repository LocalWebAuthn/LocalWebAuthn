/**
 * End-to-end proof that a software authenticator is just a signature.
 *
 * No mocked ceremonies here: `@localwebauthn/client` builds real
 * `clientDataJSON`, `authenticatorData`, CBOR attestation and DER signatures,
 * and the real `@simplewebauthn/server` verification path checks them. If the
 * design's central claim is wrong — that a headless client can complete a
 * WebAuthn ceremony without a browser, a human, or a biometric — these tests
 * fail.
 */

import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';

import Database from 'better-sqlite3';
import { beforeEach, describe, expect, it } from 'vitest';

import {
  createAssertionResponse,
  createDpopProof,
  createRegistrationResponse,
  ES256,
  encodeBase64Url,
  formatCredentialFile,
  generateKeyStore,
  importKeyStore,
  type MachineKeyStore,
  parseCredentialFile,
  parseCredentialPayload,
  type SoftwareCredential,
} from '../../packages/client/src/index.js';
import type { AuthUser } from '../../packages/server/src/index.js';
import { createUserHandle, LocalWebAuthn } from '../../packages/server/src/index.js';
import { verifyDpopProof } from '../../packages/server/src/dpop.js';
import { migrateSqlite, SqliteLocalWebAuthnStore } from '../../packages/server/src/sqlite.js';

const RP_ID = 'localhost';
const ORIGIN = 'http://localhost:4173';

function harness(
  credentialKinds?: ConstructorParameters<typeof LocalWebAuthn>[0]['credentialKinds'],
) {
  const database = new Database(':memory:');
  migrateSqlite(database);
  const user: AuthUser = {
    id: 'user-1',
    name: 'person@example.test',
    displayName: 'A Person',
    active: true,
    webAuthnUserHandle: createUserHandle(),
  };
  const auth = new LocalWebAuthn({
    rpName: 'Round Trip',
    rpId: RP_ID,
    expectedOrigins: ORIGIN,
    store: new SqliteLocalWebAuthnStore(database),
    users: { getUser: async (id) => (id === user.id ? user : null) },
    credentialKinds,
  });
  return { auth, user, database };
}

/** Register a software credential through the real verification path. */
async function enroll(
  auth: LocalWebAuthn,
  sessionToken: string | undefined,
  enrollmentSessionToken: string | undefined,
  credentialKind?: string,
  label?: string,
) {
  const { keyStore, exportPrivateKey } = await generateKeyStore(ES256);
  const options = await auth.registrationOptions({
    sessionToken,
    enrollmentSessionToken,
    credentialKind,
  });
  const { response, credentialId } = await createRegistrationResponse({
    keyStore,
    challenge: options.options.challenge,
    rpId: RP_ID,
    origin: ORIGIN,
  });
  const verified = await auth.verifyRegistration({
    response: response as unknown as RegistrationResponseJSON,
    challengeToken: options.challengeToken,
    sessionToken,
    enrollmentSessionToken,
    label,
  });
  return { keyStore, exportPrivateKey, credentialId, verified };
}

/** A first credential for a user who has none, via the enrollment-grant path. */
async function bootstrap(auth: LocalWebAuthn, credentialKind?: string, label?: string) {
  const issue = await auth.issueEnrollment('user-1');
  const exchange = await auth.exchangeEnrollment(issue.enrollmentToken);
  return enroll(auth, undefined, exchange.enrollmentSessionToken, credentialKind, label);
}

async function assertOnce(
  auth: LocalWebAuthn,
  keyStore: MachineKeyStore,
  credential: SoftwareCredential,
  credentialKinds?: (string | null)[],
) {
  const options = await auth.authenticationOptions({ credentialKinds });
  const response = await createAssertionResponse({
    keyStore,
    credential,
    challenge: options.options.challenge,
  });
  return auth.verifyAuthentication({
    response: response as unknown as AuthenticationResponseJSON,
    challengeToken: options.challengeToken,
  });
}

describe('software authenticator against the real verification path', () => {
  let fixture: ReturnType<typeof harness>;

  beforeEach(() => {
    fixture = harness();
  });

  it('registers and authenticates with no browser involved', async () => {
    const { auth, user } = fixture;
    const { keyStore, credentialId, verified } = await bootstrap(auth);
    expect(verified.verified).toBe(true);

    const credential: SoftwareCredential = {
      credentialId,
      userHandle: user.webAuthnUserHandle,
      rpId: RP_ID,
      origin: ORIGIN,
    };
    const authenticated = await assertOnce(auth, keyStore, credential);
    expect(authenticated.verified).toBe(true);
    expect(authenticated.credentialId).toBe(encodeBase64Url(credentialId));
  });

  it('records an honest credential row rather than a device passkey', async () => {
    const { auth } = fixture;
    await bootstrap(auth, 'service', "Perry's Blah maintenance script");
    const [credential] = await auth.listCredentials('user-1');

    expect(credential.kind).toBe('service');
    expect(credential.label).toBe("Perry's Blah maintenance script");
    // The two fields that would otherwise read as a human with a hardware
    // authenticator.
    expect(credential.deviceType).toBe('singleDevice');
    expect(credential.backedUp).toBe(false);
  });

  it('defaults the label to the kind instead of "Device passkey"', async () => {
    const { auth } = fixture;
    await bootstrap(auth, 'service');
    const [credential] = await auth.listCredentials('user-1');
    expect(credential.label).toBe('service');
  });

  it('opens many concurrent sessions from one credential', async () => {
    const { auth, user } = fixture;
    const { keyStore, credentialId } = await bootstrap(auth, 'service');
    const credential: SoftwareCredential = {
      credentialId,
      userHandle: user.webAuthnUserHandle,
      rpId: RP_ID,
      origin: ORIGIN,
    };

    // signCount stays 0, so the counter compare-and-swap is 0 -> 0 and parallel
    // ceremonies never contend. A strict counter would make these fight.
    const sessions = await Promise.all(
      Array.from({ length: 8 }, () => assertOnce(auth, keyStore, credential, ['service'])),
    );
    const tokens = new Set(sessions.map((session) => session.sessionToken));
    expect(tokens.size).toBe(8);

    for (const session of sessions) {
      expect(await auth.resolveSession(session.sessionToken)).not.toBeNull();
    }
  });

  it('reports the credential kind on the assertion and the session', async () => {
    const { auth, user } = fixture;
    const { keyStore, credentialId } = await bootstrap(auth, 'service');
    const authenticated = await assertOnce(
      auth,
      keyStore,
      { credentialId, userHandle: user.webAuthnUserHandle, rpId: RP_ID, origin: ORIGIN },
      ['service'],
    );
    expect(authenticated.credentialKind).toBe('service');

    const resolved = await auth.resolveSession(authenticated.sessionToken);
    expect(resolved?.session.credentialKind).toBe('service');
  });
});

describe('restrictions on API credentials', () => {
  it('refuses a service credential at a route that did not ask for it', async () => {
    const { auth, user } = harness({ service: { interactive: false } });
    const { keyStore, credentialId } = await bootstrap(auth, 'service');
    const credential: SoftwareCredential = {
      credentialId,
      userHandle: user.webAuthnUserHandle,
      rpId: RP_ID,
      origin: ORIGIN,
    };

    // The browser sign-in route names no kinds, so a non-interactive kind is out.
    await expect(assertOnce(auth, keyStore, credential)).rejects.toMatchObject({
      code: 'authentication_failed',
    });
    // The machine route names it, so the same credential succeeds.
    await expect(assertOnce(auth, keyStore, credential, ['service'])).resolves.toMatchObject({
      verified: true,
    });
  });

  it('refuses a person credential at the machine route', async () => {
    const { auth, user } = harness({ service: { interactive: false } });
    const { keyStore, credentialId } = await bootstrap(auth, 'person');
    const credential: SoftwareCredential = {
      credentialId,
      userHandle: user.webAuthnUserHandle,
      rpId: RP_ID,
      origin: ORIGIN,
    };
    await expect(assertOnce(auth, keyStore, credential, ['service'])).rejects.toMatchObject({
      code: 'authentication_failed',
    });
  });

  it('stops a service session from registering another credential', async () => {
    const { auth } = harness({ service: { interactive: false, canRegister: false } });
    const { verified } = await bootstrap(auth, 'service');

    // Without this, a leaked .env key mints a spare credential and outlives
    // revocation of the first — revocation would stop being a remedy.
    await expect(
      auth.registrationOptions({ sessionToken: verified.sessionToken }),
    ).rejects.toMatchObject({ code: 'registration_not_permitted' });
  });

  it('still lets a person session register another credential', async () => {
    const { auth } = harness({ service: { interactive: false, canRegister: false } });
    const { verified } = await bootstrap(auth, 'person');
    await expect(
      auth.registrationOptions({ sessionToken: verified.sessionToken }),
    ).resolves.toHaveProperty('challengeToken');
  });

  it('scopes the last-credential guard to the credential kind', async () => {
    const { auth } = harness();
    const person = await bootstrap(auth, 'person');
    await enroll(auth, person.verified.sessionToken, undefined, 'service');

    const [personCredential] = (await auth.listCredentials('user-1')).filter(
      (credential) => credential.kind === 'person',
    );
    // Two active credentials, but only one of each kind: the service credential
    // must not count as the person's fallback.
    await expect(auth.revokeCredential('user-1', personCredential.id)).rejects.toMatchObject({
      code: 'last_credential',
    });
  });

  it('gives a service kind its own session lifetime', async () => {
    const { auth, user } = harness({
      service: { interactive: false, sessionAbsoluteMs: 60_000 },
    });
    const { keyStore, credentialId } = await bootstrap(auth, 'service');
    const before = Date.now();
    const authenticated = await assertOnce(
      auth,
      keyStore,
      { credentialId, userHandle: user.webAuthnUserHandle, rpId: RP_ID, origin: ORIGIN },
      ['service'],
    );
    expect(authenticated.expiresAt).toBeLessThanOrEqual(before + 60_000 + 1_000);
  });
});

describe('DPoP proofs bound to the credential key', () => {
  it('verifies a proof signed by the same key as the assertion', async () => {
    const { auth, user, database } = harness();
    const { keyStore, credentialId } = await bootstrap(auth, 'service');
    const authenticated = await assertOnce(auth, keyStore, {
      credentialId,
      userHandle: user.webAuthnUserHandle,
      rpId: RP_ID,
      origin: ORIGIN,
    });

    const url = `${ORIGIN}/api/reports`;
    const proof = await createDpopProof({
      keyStore,
      method: 'POST',
      url,
      accessToken: authenticated.sessionToken,
    });

    const row = database
      .prepare('SELECT public_key FROM localwebauthn_credentials WHERE id = ?')
      .get(encodeBase64Url(credentialId)) as { public_key: Buffer };

    // The expected thumbprint comes from the stored credential, so there is no
    // per-session key material anywhere.
    const verification = await verifyDpopProof({
      proof,
      method: 'POST',
      url,
      accessToken: authenticated.sessionToken,
      publicKeyCose: new Uint8Array(row.public_key),
    });
    expect(verification).toMatchObject({ valid: true });
  });

  it('rejects a proof from a different key, a different route, and a different token', async () => {
    const { auth, user, database } = harness();
    const { keyStore, credentialId } = await bootstrap(auth, 'service');
    const authenticated = await assertOnce(auth, keyStore, {
      credentialId,
      userHandle: user.webAuthnUserHandle,
      rpId: RP_ID,
      origin: ORIGIN,
    });
    const row = database
      .prepare('SELECT public_key FROM localwebauthn_credentials WHERE id = ?')
      .get(encodeBase64Url(credentialId)) as { public_key: Buffer };
    const publicKeyCose = new Uint8Array(row.public_key);
    const url = `${ORIGIN}/api/reports`;
    const base = { method: 'POST', url, accessToken: authenticated.sessionToken, publicKeyCose };

    const stranger = await generateKeyStore(ES256);
    const forged = await createDpopProof({
      keyStore: stranger.keyStore,
      method: 'POST',
      url,
      accessToken: authenticated.sessionToken,
    });
    expect(await verifyDpopProof({ ...base, proof: forged })).toMatchObject({
      valid: false,
      reason: 'key_mismatch',
    });

    const good = await createDpopProof({
      keyStore,
      method: 'POST',
      url,
      accessToken: authenticated.sessionToken,
    });
    expect(
      await verifyDpopProof({ ...base, proof: good, url: `${ORIGIN}/api/other` }),
    ).toMatchObject({ valid: false, reason: 'htu_mismatch' });
    expect(await verifyDpopProof({ ...base, proof: good, method: 'GET' })).toMatchObject({
      valid: false,
      reason: 'htm_mismatch',
    });
    expect(await verifyDpopProof({ ...base, proof: good, accessToken: 'other' })).toMatchObject({
      valid: false,
      reason: 'ath_mismatch',
    });
    expect(
      await verifyDpopProof({ ...base, proof: good, now: Date.now() + 10 * 60_000 }),
    ).toMatchObject({ valid: false, reason: 'iat_out_of_window' });
  });

  it('claims a jti exactly once', async () => {
    const database = new Database(':memory:');
    migrateSqlite(database);
    const store = new SqliteLocalWebAuthnStore(database);
    const jtiHash = new Uint8Array(32).fill(7);
    expect(await store.claimDpopProof(jtiHash, Date.now() + 60_000)).toBe(true);
    expect(await store.claimDpopProof(jtiHash, Date.now() + 60_000)).toBe(false);
  });
});

describe('the two-line credential file', () => {
  it('round-trips through format and parse', async () => {
    const { keyStore, exportPrivateKey } = await generateKeyStore(ES256);
    const key = await exportPrivateKey();
    const payload = {
      v: 1 as const,
      baseUrl: ORIGIN,
      rpId: RP_ID,
      origin: ORIGIN,
      credentialId: encodeBase64Url(new Uint8Array(32).fill(1)),
      userHandle: encodeBase64Url(new Uint8Array(32).fill(2)),
      alg: ES256,
    };

    const text = formatCredentialFile(payload, key, "Perry's Blah maintenance script");
    expect(text.split('\n').filter((line) => line && !line.startsWith('#'))).toHaveLength(2);

    const parsed = parseCredentialFile(text);
    if (!parsed) {
      throw new Error('the formatted file did not parse');
    }
    expect(parseCredentialPayload(parsed.payload)).toEqual(payload);

    // The imported key must produce the same signatures as the original.
    const reopened = await importKeyStore(parsed.key, ES256);
    expect(await reopened.publicKeyCose()).toEqual(await keyStore.publicKeyCose());
    expect(await reopened.publicJwk()).toEqual(await keyStore.publicJwk());
  });

  it('refuses an apostrophe that would break shell sourcing', async () => {
    const payload = {
      v: 1 as const,
      baseUrl: "http://localhost/'",
      rpId: RP_ID,
      origin: ORIGIN,
      credentialId: 'a',
      userHandle: 'b',
      alg: ES256,
    };
    expect(() => formatCredentialFile(payload, 'key')).toThrow(/apostrophe/u);
  });

  it('refuses a payload version it does not understand', () => {
    expect(() => parseCredentialPayload(JSON.stringify({ v: 99 }))).toThrow(/Unsupported/u);
  });
});
