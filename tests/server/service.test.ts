import type {
  AuthenticationResponseJSON,
  Base64URLString,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';

import Database from 'better-sqlite3';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type {
  AuthUser,
  CeremonyProvider,
  LocalWebAuthnEvent,
} from '../../packages/server/src/index.js';
import {
  createUserHandle,
  encodeBase64Url,
  LocalWebAuthn,
  LocalWebAuthnError,
} from '../../packages/server/src/index.js';
import { migrateSqlite, SqliteLocalWebAuthnStore } from '../../packages/server/src/sqlite.js';

const credentialId = 'credential-id' as Base64URLString;

function registrationResponse(): RegistrationResponseJSON {
  return {
    id: credentialId,
    rawId: credentialId,
    response: {
      clientDataJSON: 'client-data',
      attestationObject: 'attestation',
      transports: ['internal'],
      publicKeyAlgorithm: -7,
      publicKey: 'public-key',
      authenticatorData: 'authenticator-data',
    },
    type: 'public-key',
    clientExtensionResults: {},
    authenticatorAttachment: 'platform',
  };
}

function authenticationResponse(userHandle: Uint8Array): AuthenticationResponseJSON {
  return {
    id: credentialId,
    rawId: credentialId,
    response: {
      clientDataJSON: 'client-data',
      authenticatorData: 'authenticator-data',
      signature: 'signature',
      userHandle: encodeBase64Url(userHandle),
    },
    type: 'public-key',
    clientExtensionResults: {},
    authenticatorAttachment: 'platform',
  };
}

function fakeCeremonies() {
  return {
    generateRegistrationOptions: vi.fn(async (options: { userID: Uint8Array }) => ({
      challenge: 'registration-challenge',
      rp: { id: 'localhost', name: 'LocalWebAuthn Test' },
      user: {
        id: encodeBase64Url(options.userID),
        name: 'user@example.test',
        displayName: 'Test User',
      },
      pubKeyCredParams: [],
      timeout: 300_000,
      attestation: 'none',
      authenticatorSelection: {
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'required',
      },
      excludeCredentials: [],
      extensions: {},
      hints: [],
    })),
    verifyRegistrationResponse: vi.fn(async () => ({
      verified: true,
      registrationInfo: {
        fmt: 'none',
        aaguid: '00000000-0000-0000-0000-000000000000',
        credential: {
          id: credentialId,
          publicKey: new Uint8Array([1, 2, 3]),
          counter: 0,
          transports: ['internal'],
        },
        credentialType: 'public-key',
        attestationObject: new Uint8Array(),
        userVerified: true,
        credentialDeviceType: 'multiDevice',
        credentialBackedUp: true,
        origin: 'http://localhost:5173',
        rpID: 'localhost',
      },
    })),
    generateAuthenticationOptions: vi.fn(async () => ({
      challenge: 'authentication-challenge',
      timeout: 300_000,
      rpId: 'localhost',
      allowCredentials: [],
      userVerification: 'required',
      extensions: {},
      hints: [],
    })),
    verifyAuthenticationResponse: vi.fn(async () => ({
      verified: true,
      authenticationInfo: {
        newCounter: 1,
        credentialID: credentialId,
        userVerified: true,
        credentialDeviceType: 'multiDevice',
        credentialBackedUp: true,
        origin: 'http://localhost:5173',
        rpID: 'localhost',
      },
    })),
  } as unknown as CeremonyProvider;
}

describe('LocalWebAuthn lifecycle', () => {
  let database: Database.Database;
  let user: AuthUser;
  let now: number;
  let randomValue: number;
  let events: LocalWebAuthnEvent[];
  let ceremonies: CeremonyProvider;
  let auth: LocalWebAuthn;

  beforeEach(() => {
    database = new Database(':memory:');
    database.pragma('foreign_keys = ON');
    migrateSqlite(database);
    user = {
      id: 'user-1',
      webAuthnUserHandle: createUserHandle(() => new Uint8Array(32).fill(11)),
      name: 'user@example.test',
      displayName: 'Test User',
      active: true,
    };
    now = 10_000;
    randomValue = 20;
    events = [];
    ceremonies = fakeCeremonies();
    auth = new LocalWebAuthn({
      rpName: 'LocalWebAuthn Test',
      rpId: 'localhost',
      expectedOrigins: 'http://localhost:5173',
      store: new SqliteLocalWebAuthnStore(database),
      users: {
        getUser: async (userId) => (userId === user.id ? user : null),
      },
      ceremonies,
      now: () => now,
      randomBytes: (length) => new Uint8Array(length).fill(randomValue++),
      onEvent: (event) => {
        events.push(event);
      },
    });
  });

  it('enrolls, authenticates, resolves, and revokes a passkey session', async () => {
    const issue = await auth.issueEnrollment(user.id, 'admin-1');
    expect(issue.enrollmentUrl).toMatch(/^http:\/\/localhost:5173\/enroll#token=[a-z2-7]{52}$/u);

    const exchange = await auth.exchangeEnrollment(issue.enrollmentToken);
    expect(exchange.user).toEqual({
      id: user.id,
      name: user.name,
      displayName: user.displayName,
    });

    const registration = await auth.registrationOptions({
      enrollmentSessionToken: exchange.enrollmentSessionToken,
    });
    const registered = await auth.verifyRegistration({
      response: registrationResponse(),
      challengeToken: registration.challengeToken,
      enrollmentSessionToken: exchange.enrollmentSessionToken,
    });
    expect(registered.verified).toBe(true);
    await expect(auth.resolveSession(registered.sessionToken)).resolves.toMatchObject({
      user: { id: user.id },
      session: { credentialId },
    });

    const authentication = await auth.authenticationOptions();
    const authenticated = await auth.verifyAuthentication({
      response: authenticationResponse(user.webAuthnUserHandle),
      challengeToken: authentication.challengeToken,
    });
    expect(authenticated).toMatchObject({
      verified: true,
      credentialId,
      user: { id: user.id },
    });
    await expect(auth.revokeSession(authenticated.sessionToken)).resolves.toBe(true);
    await expect(auth.resolveSession(authenticated.sessionToken)).resolves.toBeNull();

    expect(events.map(({ type }) => type)).toEqual([
      'enrollment.issued',
      'enrollment.exchanged',
      'enrollment.completed',
      'credential.registered',
      'session.created',
      'credential.authenticated',
      'session.created',
      'session.revoked',
    ]);
    database.close();
  });

  it('rejects a ceremony after its enrollment grant is replaced', async () => {
    const firstIssue = await auth.issueEnrollment(user.id);
    const firstExchange = await auth.exchangeEnrollment(firstIssue.enrollmentToken);
    const oldCeremony = await auth.registrationOptions({
      enrollmentSessionToken: firstExchange.enrollmentSessionToken,
    });

    await auth.issueEnrollment(user.id);

    await expect(
      auth.verifyRegistration({
        response: registrationResponse(),
        challengeToken: oldCeremony.challengeToken,
        enrollmentSessionToken: firstExchange.enrollmentSessionToken,
      }),
    ).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({
        code: 'enrollment_not_authorized',
        status: 403,
      }),
    );
    await expect(auth.listCredentials(user.id)).resolves.toHaveLength(0);
    database.close();
  });

  it('burns challenges after one failed authentication attempt', async () => {
    const issue = await auth.issueEnrollment(user.id);
    const exchange = await auth.exchangeEnrollment(issue.enrollmentToken);
    const registration = await auth.registrationOptions({
      enrollmentSessionToken: exchange.enrollmentSessionToken,
    });
    await auth.verifyRegistration({
      response: registrationResponse(),
      challengeToken: registration.challengeToken,
      enrollmentSessionToken: exchange.enrollmentSessionToken,
    });

    const authentication = await auth.authenticationOptions();
    const wrongHandle = new Uint8Array(32).fill(99);
    await expect(
      auth.verifyAuthentication({
        response: authenticationResponse(wrongHandle),
        challengeToken: authentication.challengeToken,
      }),
    ).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({
        code: 'authentication_failed',
      }),
    );
    await expect(
      auth.verifyAuthentication({
        response: authenticationResponse(user.webAuthnUserHandle),
        challengeToken: authentication.challengeToken,
      }),
    ).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({
        code: 'invalid_ceremony',
      }),
    );
    database.close();
  });

  it('enforces idle expiry and active-user status', async () => {
    const issue = await auth.issueEnrollment(user.id);
    const exchange = await auth.exchangeEnrollment(issue.enrollmentToken);
    const registration = await auth.registrationOptions({
      enrollmentSessionToken: exchange.enrollmentSessionToken,
    });
    const registered = await auth.verifyRegistration({
      response: registrationResponse(),
      challengeToken: registration.challengeToken,
      enrollmentSessionToken: exchange.enrollmentSessionToken,
    });

    now += auth.config.durations.sessionIdleMs + 1;
    await expect(auth.resolveSession(registered.sessionToken)).resolves.toBeNull();
    user.active = false;
    await expect(auth.issueEnrollment(user.id)).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({
        code: 'invalid_enrollment',
      }),
    );
    database.close();
  });

  it('protects the last active credential unless recovery explicitly allows it', async () => {
    const issue = await auth.issueEnrollment(user.id);
    const exchange = await auth.exchangeEnrollment(issue.enrollmentToken);
    const registration = await auth.registrationOptions({
      enrollmentSessionToken: exchange.enrollmentSessionToken,
    });
    await auth.verifyRegistration({
      response: registrationResponse(),
      challengeToken: registration.challengeToken,
      enrollmentSessionToken: exchange.enrollmentSessionToken,
    });

    await expect(auth.revokeCredential(user.id, credentialId)).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({ code: 'last_credential' }),
    );
    await expect(
      auth.revokeCredential(user.id, credentialId, { allowLastCredential: true }),
    ).resolves.toBe(true);
    database.close();
  });
});
