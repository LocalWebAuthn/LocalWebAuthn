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
    const issue = await auth.issueEnrollment(user.id, { approvedByUserId: 'admin-1' });
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
    expect(events.find((event) => event.type === 'credential.registered')).toMatchObject({
      type: 'credential.registered',
      createdVia: 'enrollment',
    });
    database.close();
  });

  it('reports superseded grants from issueEnrollment for durable host audit', async () => {
    const first = await auth.issueEnrollment(user.id);
    expect(first.supersededGrantIds).toEqual([]);

    const second = await auth.issueEnrollment(user.id);
    expect(second.supersededGrantIds).toEqual([first.grantId]);
    // The best-effort event names the same grant the return value reports.
    expect(events).toContainEqual(
      expect.objectContaining({ type: 'enrollment.revoked', grantId: first.grantId }),
    );
    database.close();
  });

  /**
   * A refused enrollment link is one error with four meanings, and the host has to
   * pick a message. Only `used` is worth raising with the person holding it: the
   * link is single-use, so if they did not spend it, somebody else did.
   */
  it('says why an enrollment link was refused, and only alarms for a spent one', async () => {
    const issue = await auth.issueEnrollment(user.id);
    await auth.exchangeEnrollment(issue.enrollmentToken);

    // Spent. This is the one that earns the warning, and the message says so.
    await expect(auth.exchangeEnrollment(issue.enrollmentToken)).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({
        code: 'invalid_enrollment',
        status: 403,
        enrollmentState: 'used',
        message: 'This enrollment link has already been used.',
      }),
    );
    expect(events).toContainEqual(
      expect.objectContaining({ type: 'enrollment.rejected', state: 'used', userId: user.id }),
    );

    // Superseded: a newer invitation revoked this one. Ordinary, and must not be
    // reported as a possible compromise.
    const replaced = await auth.issueEnrollment(user.id);
    await auth.issueEnrollment(user.id);
    await expect(auth.exchangeEnrollment(replaced.enrollmentToken)).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({
        enrollmentState: 'superseded',
        message: 'The enrollment link is invalid or expired.',
      }),
    );

    // Expired, unspent.
    const stale = await auth.issueEnrollment(user.id);
    now += 31 * 60_000;
    await expect(auth.exchangeEnrollment(stale.enrollmentToken)).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({ enrollmentState: 'expired' }),
    );

    // A syntactically valid token no grant carries — a probe, or a mangled URL.
    await expect(auth.exchangeEnrollment('a'.repeat(52))).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({ enrollmentState: 'unknown' }),
    );
    expect(events).toContainEqual(
      expect.objectContaining({ type: 'enrollment.rejected', state: 'unknown', userId: null }),
    );
    database.close();
  });

  it('leaves the state off when the store cannot diagnose', async () => {
    const store = new SqliteLocalWebAuthnStore(database);
    // A custom store predating this method: the exchange still refuses, the host
    // still gets its error, and nothing pretends to know why.
    // Methods are bound to the target: called through the proxy, `this` would be
    // the proxy, and the adapter's `#database` private field would be unreachable.
    const undiagnosing = new Proxy(store, {
      get(target, property) {
        if (property === 'enrollmentGrantState') {
          return undefined;
        }
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === 'function' ? (value.bind(target) as unknown) : value;
      },
    });
    const plain = new LocalWebAuthn({
      rpName: 'LocalWebAuthn Test',
      rpId: 'localhost',
      expectedOrigins: 'http://localhost:5173',
      store: undiagnosing,
      users: { getUser: async (userId) => (userId === user.id ? user : null) },
      ceremonies,
      now: () => now,
      randomBytes: (length) => new Uint8Array(length).fill(randomValue++),
      onEvent: (event) => {
        events.push(event);
      },
    });

    const issue = await plain.issueEnrollment(user.id);
    await plain.exchangeEnrollment(issue.enrollmentToken);
    const error = await plain
      .exchangeEnrollment(issue.enrollmentToken)
      .catch((cause: unknown) => cause);
    expect(error).toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({ code: 'invalid_enrollment' }),
    );
    expect(error).not.toHaveProperty('enrollmentState');
    expect(events.at(-1)).toMatchObject({
      type: 'enrollment.rejected',
      state: 'unknown',
      userId: null,
    });
    database.close();
  });

  /**
   * The exchange *succeeded* here — the token was spent by this very call — so its
   * state is `used`. Reporting that would tell the rightful holder somebody had
   * beaten them to their own link, when the truth is only that the account is
   * deactivated. So this path is deliberately left undiagnosed.
   */
  it('does not accuse the rightful holder when the user is deactivated', async () => {
    const issue = await auth.issueEnrollment(user.id);
    user.active = false;

    const error = await auth
      .exchangeEnrollment(issue.enrollmentToken)
      .catch((cause: unknown) => cause);
    expect(error).toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({
        code: 'invalid_enrollment',
        status: 403,
      }),
    );
    expect((error as LocalWebAuthnError).enrollmentState).toBeUndefined();
    expect(events).not.toContainEqual(expect.objectContaining({ type: 'enrollment.rejected' }));
    database.close();
  });

  it('refuses enrollment exchange and registration for a user deactivated mid-flow', async () => {
    const issue = await auth.issueEnrollment(user.id);
    user.active = false;
    await expect(auth.exchangeEnrollment(issue.enrollmentToken)).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({
        code: 'invalid_enrollment',
        status: 403,
      }),
    );

    user.active = true;
    const secondIssue = await auth.issueEnrollment(user.id);
    const exchange = await auth.exchangeEnrollment(secondIssue.enrollmentToken);
    const registration = await auth.registrationOptions({
      enrollmentSessionToken: exchange.enrollmentSessionToken,
    });
    user.active = false;
    await expect(
      auth.verifyRegistration({
        response: registrationResponse(),
        challengeToken: registration.challengeToken,
        enrollmentSessionToken: exchange.enrollmentSessionToken,
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

  it('refuses authentication and session use for a deactivated user with a valid passkey', async () => {
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
    const authentication = await auth.authenticationOptions();
    user.active = false;

    // The ceremony refuses; the credential is not confirmed as working.
    await expect(
      auth.verifyAuthentication({
        response: authenticationResponse(user.webAuthnUserHandle),
        challengeToken: authentication.challengeToken,
      }),
    ).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({
        code: 'authentication_failed',
        status: 401,
      }),
    );
    // Existing sessions stop resolving and cannot authorize more passkeys.
    await expect(auth.resolveSession(registered.sessionToken)).resolves.toBeNull();
    await expect(
      auth.registrationOptions({ sessionToken: registered.sessionToken }),
    ).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({
        code: 'enrollment_not_authorized',
        status: 403,
      }),
    );
    database.close();
  });

  it('revokes all user sessions without touching credentials, sparing an excepted one', async () => {
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
    const authentication = await auth.authenticationOptions();
    const authenticated = await auth.verifyAuthentication({
      response: authenticationResponse(user.webAuthnUserHandle),
      challengeToken: authentication.challengeToken,
    });

    // "Sign out everywhere else": the excepted session survives.
    await expect(
      auth.revokeUserSessions(user.id, { exceptSessionToken: authenticated.sessionToken }),
    ).resolves.toBe(1);
    await expect(auth.resolveSession(registered.sessionToken)).resolves.toBeNull();
    await expect(auth.resolveSession(authenticated.sessionToken)).resolves.not.toBeNull();

    // "Sign out everywhere": no exception, and calling again finds nothing.
    await expect(auth.revokeUserSessions(user.id)).resolves.toBe(1);
    await expect(auth.resolveSession(authenticated.sessionToken)).resolves.toBeNull();
    await expect(auth.revokeUserSessions(user.id)).resolves.toBe(0);

    // Credentials and pending grants are untouched; only sessions ended.
    await expect(auth.listCredentials(user.id)).resolves.toHaveLength(1);
    expect(events.filter((event) => event.type === 'user.sessions_revoked')).toEqual([
      expect.objectContaining({ userId: user.id, count: 1 }),
      expect.objectContaining({ userId: user.id, count: 1 }),
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

  it('revokes all authentication state for a user', async () => {
    // Enroll and register a passkey to create a credential and session.
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

    // Issue a second enrollment grant to ensure pending grants are also revoked.
    const secondIssue = await auth.issueEnrollment(user.id);
    const pendingGrantToken = secondIssue.enrollmentToken;

    // Verify pre-conditions: credential exists, session resolves, grant is pending.
    await expect(auth.listCredentials(user.id)).resolves.toHaveLength(1);
    await expect(auth.resolveSession(registered.sessionToken)).resolves.not.toBeNull();

    // Exchange the second grant to verify it is still usable before revocation.
    const secondExchange = await auth.exchangeEnrollment(pendingGrantToken);
    expect(secondExchange.user.id).toBe(user.id);

    // Revoke all authentication.
    await auth.revokeUserAuthentication(user.id);

    // Credentials are revoked.
    await expect(auth.listCredentials(user.id)).resolves.toHaveLength(0);
    await expect(auth.listCredentials(user.id, true)).resolves.toMatchObject([
      { revokedAt: expect.any(Number) as number },
    ]);

    // Sessions are revoked.
    await expect(auth.resolveSession(registered.sessionToken)).resolves.toBeNull();

    // The second enrollment grant (not yet completed) is also revoked.
    await expect(auth.exchangeEnrollment(pendingGrantToken)).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({
        code: 'invalid_enrollment',
        status: 403,
      }),
    );

    // The exchanged enrollment session for the second grant is also invalidated.
    await expect(
      auth.registrationOptions({
        enrollmentSessionToken: secondExchange.enrollmentSessionToken,
      }),
    ).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({
        code: 'enrollment_not_authorized',
        status: 403,
      }),
    );

    database.close();
  });

  it('emits an audit event when a prior enrollment grant is implicitly revoked', async () => {
    const firstIssue = await auth.issueEnrollment(user.id);
    events.length = 0;

    // Issuing a second enrollment for the same user implicitly revokes the first.
    await auth.issueEnrollment(user.id);

    // The first grant should no longer be exchangeable.
    await expect(auth.exchangeEnrollment(firstIssue.enrollmentToken)).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({
        code: 'invalid_enrollment',
        status: 403,
      }),
    );

    // An event signaling the implicit revocation should have been emitted.
    const revocationEvents = events.filter((event) => event.type === 'enrollment.revoked');
    expect(revocationEvents).toHaveLength(1);
    expect(revocationEvents[0]).toMatchObject({
      type: 'enrollment.revoked',
      userId: user.id,
      grantId: firstIssue.grantId,
    });

    database.close();
  });

  it('registers an additional passkey authorized by an authenticated session', async () => {
    const issue = await auth.issueEnrollment(user.id);
    const exchange = await auth.exchangeEnrollment(issue.enrollmentToken);
    const firstRegistration = await auth.registrationOptions({
      enrollmentSessionToken: exchange.enrollmentSessionToken,
    });
    const first = await auth.verifyRegistration({
      response: registrationResponse(),
      challengeToken: firstRegistration.challengeToken,
      enrollmentSessionToken: exchange.enrollmentSessionToken,
    });

    const secondCredentialId = 'credential-id-2' as Base64URLString;
    (ceremonies.verifyRegistrationResponse as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      verified: true,
      registrationInfo: {
        fmt: 'none',
        aaguid: '00000000-0000-0000-0000-000000000000',
        credential: {
          id: secondCredentialId,
          publicKey: new Uint8Array([4, 5, 6]),
          counter: 0,
          transports: ['internal'],
        },
        credentialType: 'public-key',
        attestationObject: new Uint8Array(),
        userVerified: true,
        credentialDeviceType: 'singleDevice',
        credentialBackedUp: false,
        origin: 'http://localhost:5173',
        rpID: 'localhost',
      },
    });

    events.length = 0;
    const secondRegistration = await auth.registrationOptions({
      sessionToken: first.sessionToken,
    });
    const second = await auth.verifyRegistration({
      response: { ...registrationResponse(), id: secondCredentialId, rawId: secondCredentialId },
      challengeToken: secondRegistration.challengeToken,
      sessionToken: first.sessionToken,
      label: 'Security key',
    });
    expect(second.verified).toBe(true);
    await expect(auth.listCredentials(user.id)).resolves.toHaveLength(2);
    expect(events.map(({ type }) => type)).toEqual(['credential.registered', 'session.created']);
    expect(events[0]).toMatchObject({
      type: 'credential.registered',
      createdVia: 'credential',
    });
    expect(events.some((event) => event.type === 'enrollment.completed')).toBe(false);
    database.close();
  });

  it('keeps credentials after logout and cleanup so sign-in still works', async () => {
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

    events.length = 0;
    await expect(auth.revokeSession(registered.sessionToken)).resolves.toBe(true);
    expect(events).toContainEqual(
      expect.objectContaining({
        type: 'session.revoked',
        userId: user.id,
        credentialId,
      }),
    );

    // Past absolute session lifetime; cleanup reaps sessions, not credentials.
    now += 9 * 60 * 60_000;
    const cleaned = await auth.cleanup();
    expect(cleaned.sessions).toBeGreaterThanOrEqual(1);
    await expect(auth.listCredentials(user.id)).resolves.toHaveLength(1);

    const authentication = await auth.authenticationOptions();
    await expect(
      auth.verifyAuthentication({
        response: authenticationResponse(user.webAuthnUserHandle),
        challengeToken: authentication.challengeToken,
      }),
    ).resolves.toMatchObject({ verified: true, credentialId });
    database.close();
  });

  it('rejects a non-increasing non-zero authenticator counter', async () => {
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

    // Advance counter to 3, then try to authenticate with newCounter 3 again.
    (ceremonies.verifyAuthenticationResponse as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce({
        verified: true,
        authenticationInfo: {
          newCounter: 3,
          credentialID: credentialId,
          userVerified: true,
          credentialDeviceType: 'multiDevice',
          credentialBackedUp: true,
          origin: 'http://localhost:5173',
          rpID: 'localhost',
        },
      })
      .mockResolvedValueOnce({
        verified: true,
        authenticationInfo: {
          newCounter: 3,
          credentialID: credentialId,
          userVerified: true,
          credentialDeviceType: 'multiDevice',
          credentialBackedUp: true,
          origin: 'http://localhost:5173',
          rpID: 'localhost',
        },
      });

    const first = await auth.authenticationOptions();
    await auth.verifyAuthentication({
      response: authenticationResponse(user.webAuthnUserHandle),
      challengeToken: first.challengeToken,
    });

    const second = await auth.authenticationOptions();
    await expect(
      auth.verifyAuthentication({
        response: authenticationResponse(user.webAuthnUserHandle),
        challengeToken: second.challengeToken,
      }),
    ).rejects.toEqual(
      expect.objectContaining<Partial<LocalWebAuthnError>>({
        code: 'authentication_failed',
        status: 401,
      }),
    );
    database.close();
  });

  it('emits user.authentication_revoked when bulk recovery revoke runs', async () => {
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

    events.length = 0;
    await auth.revokeUserAuthentication(user.id);
    expect(events).toContainEqual(
      expect.objectContaining({
        type: 'user.authentication_revoked',
        userId: user.id,
      }),
    );
    database.close();
  });
});
