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
  EDDSA,
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
import type {
  AuthUser,
  LocalWebAuthnEvent,
  LocalWebAuthnStore,
  SessionIdentity,
} from '../../packages/server/src/index.js';
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

  it('registers and authenticates with an Ed25519 key', async () => {
    // EDDSA is exported, so the whole -8 path has to be exercised somewhere: raw
    // 64-byte signatures rather than DER, and an OKP COSE key rather than EC2.
    const { auth, user } = fixture;
    const { keyStore } = await generateKeyStore(EDDSA);
    const issue = await auth.issueEnrollment('user-1');
    const exchange = await auth.exchangeEnrollment(issue.enrollmentToken);
    const options = await auth.registrationOptions({
      enrollmentSessionToken: exchange.enrollmentSessionToken,
    });
    const registration = await createRegistrationResponse({
      keyStore,
      challenge: options.options.challenge,
      rpId: RP_ID,
      origin: ORIGIN,
    });
    await expect(
      auth.verifyRegistration({
        response: registration.response as unknown as RegistrationResponseJSON,
        challengeToken: options.challengeToken,
        enrollmentSessionToken: exchange.enrollmentSessionToken,
      }),
    ).resolves.toMatchObject({ verified: true });

    const authenticated = await assertOnce(auth, keyStore, {
      credentialId: registration.credentialId,
      userHandle: user.webAuthnUserHandle,
      rpId: RP_ID,
      origin: ORIGIN,
    });
    expect(authenticated.verified).toBe(true);
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

describe('credential heritage', () => {
  it('records where a credential came from, and when', async () => {
    const { auth } = harness();
    const issue = await auth.issueEnrollment('user-1', { approvedByUserId: 'admin-1' });
    const exchange = await auth.exchangeEnrollment(issue.enrollmentToken);
    const root = await enroll(
      auth,
      undefined,
      exchange.enrollmentSessionToken,
      undefined,
      'laptop',
    );
    const child = await enroll(auth, root.verified.sessionToken, undefined, undefined, 'phone');

    const credentials = await auth.listCredentials('user-1');
    const rootRow = credentials.find((c) => c.id === root.verified.credentialId);
    const childRow = credentials.find((c) => c.id === child.verified.credentialId);

    // The root came from an enrollment token somebody with authority issued.
    expect(rootRow).toMatchObject({
      createdVia: 'enrollment',
      grantId: issue.grantId,
      approvedByUserId: 'admin-1',
      parentCredentialId: null,
    });
    // The child was authorized by the root's session.
    expect(childRow).toMatchObject({
      createdVia: 'credential',
      parentCredentialId: root.verified.credentialId,
      grantId: null,
      approvedByUserId: null,
    });
    // "When" was already answered.
    expect(childRow?.createdAt).toBeGreaterThanOrEqual(rootRow?.createdAt ?? 0);
  });

  it('walks the chain back to the enrollment that started it', async () => {
    const { auth } = harness();
    const issue = await auth.issueEnrollment('user-1', { approvedByUserId: 'admin-1' });
    const exchange = await auth.exchangeEnrollment(issue.enrollmentToken);
    const a = await enroll(auth, undefined, exchange.enrollmentSessionToken, undefined, 'a');
    const b = await enroll(auth, a.verified.sessionToken, undefined, undefined, 'b');
    const c = await enroll(auth, b.verified.sessionToken, undefined, undefined, 'c');

    const lineage = await auth.credentialLineage('user-1', c.verified.credentialId);
    // Root first, so the first entry is the one an administrator approved.
    expect(lineage.map((credential) => credential.label)).toEqual(['a', 'b', 'c']);
    expect(lineage[0].createdVia).toBe('enrollment');
    expect(lineage[0].approvedByUserId).toBe('admin-1');

    // The root's own lineage is just itself.
    await expect(auth.credentialLineage('user-1', a.verified.credentialId)).resolves.toHaveLength(
      1,
    );
    // An unknown credential, or another user's, yields nothing.
    await expect(auth.credentialLineage('user-1', 'nope')).resolves.toEqual([]);
    await expect(auth.credentialLineage('other', c.verified.credentialId)).resolves.toEqual([]);
  });

  it('survives the cleanup that used to destroy the trail', async () => {
    const { auth } = harness();
    const issue = await auth.issueEnrollment('user-1', { approvedByUserId: 'admin-1' });
    const exchange = await auth.exchangeEnrollment(issue.enrollmentToken);
    const root = await enroll(auth, undefined, exchange.enrollmentSessionToken, undefined, 'root');
    const child = await enroll(auth, root.verified.sessionToken, undefined, undefined, 'child');

    // Consumed challenges go on the first pass, the completed grant on the second.
    // Those rows were the only thing that ever linked these two.
    await auth.cleanup();
    await auth.cleanup();

    const lineage = await auth.credentialLineage('user-1', child.verified.credentialId);
    expect(lineage.map((credential) => credential.label)).toEqual(['root', 'child']);
    expect(lineage[0].grantId).toBe(issue.grantId);
  });

  it('reports the blast radius of a compromised credential', async () => {
    const { auth } = harness();
    const issue = await auth.issueEnrollment('user-1');
    const exchange = await auth.exchangeEnrollment(issue.enrollmentToken);
    const root = await enroll(auth, undefined, exchange.enrollmentSessionToken, undefined, 'root');
    const stolen = await enroll(auth, root.verified.sessionToken, undefined, undefined, 'stolen');
    await enroll(auth, stolen.verified.sessionToken, undefined, undefined, 'spawn');
    // A sibling of the compromised credential is not in its subtree.
    await enroll(auth, root.verified.sessionToken, undefined, undefined, 'sibling');

    const subtree = await auth.credentialDescendants('user-1', stolen.verified.credentialId);
    expect(subtree.map((credential) => credential.label)).toEqual(['stolen', 'spawn']);

    const wholeTree = await auth.credentialDescendants('user-1', root.verified.credentialId);
    expect(wholeTree.map((credential) => credential.label).sort()).toEqual([
      'root',
      'sibling',
      'spawn',
      'stolen',
    ]);
  });

  it('revokes a compromised credential together with what it enrolled', async () => {
    const { auth } = harness();
    const issue = await auth.issueEnrollment('user-1');
    const exchange = await auth.exchangeEnrollment(issue.enrollmentToken);
    const root = await enroll(auth, undefined, exchange.enrollmentSessionToken, undefined, 'root');
    // The attack: a stolen session enrols a passkey of the attacker's own, which is
    // the intended "add a passkey" feature and so cannot simply be forbidden.
    const stolen = await enroll(auth, root.verified.sessionToken, undefined, undefined, 'stolen');
    const spawn = await enroll(auth, stolen.verified.sessionToken, undefined, undefined, 'spawn');

    const revoked = await auth.revokeCredentialTree('user-1', stolen.verified.credentialId);
    expect(revoked).toEqual([stolen.verified.credentialId, spawn.verified.credentialId]);

    const active = await auth.listCredentials('user-1');
    expect(active.map((credential) => credential.label)).toEqual(['root']);

    // Idempotent: a second call finds nothing left to revoke.
    await expect(
      auth.revokeCredentialTree('user-1', stolen.verified.credentialId),
    ).resolves.toEqual([]);
  });

  it('will empty the account rather than leave a half-revoked tree', async () => {
    const { auth } = harness();
    const issue = await auth.issueEnrollment('user-1');
    const exchange = await auth.exchangeEnrollment(issue.enrollmentToken);
    const root = await enroll(auth, undefined, exchange.enrollmentSessionToken, undefined, 'root');
    await enroll(auth, root.verified.sessionToken, undefined, undefined, 'child');

    // Stopping short of the last credential would leave a partially revoked
    // subtree, which after a compromise is worse than requiring re-enrollment.
    const revoked = await auth.revokeCredentialTree('user-1', root.verified.credentialId);
    expect(revoked).toHaveLength(2);
    await expect(auth.listCredentials('user-1')).resolves.toEqual([]);
  });

  /** person 'laptop' -> service 'exporter' -> person 'phone'. */
  async function mixedChain() {
    const fixture = harness();
    const laptop = await bootstrap(fixture.auth, 'person', 'laptop');
    const exporter = await enroll(
      fixture.auth,
      laptop.verified.sessionToken,
      undefined,
      'service',
      'exporter',
    );
    const phone = await enroll(
      fixture.auth,
      exporter.verified.sessionToken,
      undefined,
      'person',
      'phone',
    );
    return { ...fixture, laptop, exporter, phone };
  }

  it('crosses kinds when unscoped, stopping the scripts a passkey provisioned', async () => {
    const { auth, laptop } = await mixedChain();

    // The consequence worth knowing about: an API credential's parent *is* the
    // person's passkey, so revoking the passkey's tree stops their scripts too.
    // Correct for a compromise, since that passkey could have minted them.
    await auth.revokeCredentialTree('user-1', laptop.verified.credentialId);
    await expect(auth.listCredentials('user-1')).resolves.toEqual([]);
  });

  it('revokes only the named kinds, still reaching through the ones it spares', async () => {
    const { auth, laptop, exporter, phone } = await mixedChain();

    const revoked = await auth.revokeCredentialTree('user-1', laptop.verified.credentialId, {
      kinds: ['person'],
    });

    // 'exporter' is spared, but 'phone' — which 'exporter' enrolled — is not:
    // sparing a node must not silently spare what it created.
    expect(revoked).toEqual([laptop.verified.credentialId, phone.verified.credentialId]);
    const active = await auth.listCredentials('user-1');
    expect(active.map((credential) => credential.label)).toEqual(['exporter']);
    expect(active[0].id).toBe(exporter.verified.credentialId);
  });

  it('leaves pre-heritage credentials honestly unknown', async () => {
    const { auth, database } = harness();
    const issue = await auth.issueEnrollment('user-1');
    const exchange = await auth.exchangeEnrollment(issue.enrollmentToken);
    const root = await enroll(
      auth,
      undefined,
      exchange.enrollmentSessionToken,
      undefined,
      'legacy',
    );
    // Simulate a row registered before heritage existed.
    database
      .prepare(
        `UPDATE localwebauthn_credentials
         SET created_via = NULL, grant_id = NULL, approved_by_user_id = NULL
         WHERE id = ?`,
      )
      .run(root.verified.credentialId);

    const [credential] = await auth.listCredentials('user-1');
    expect(credential.createdVia).toBeNull();
    // The walk still terminates, reporting the credential itself and nothing more.
    await expect(
      auth.credentialLineage('user-1', root.verified.credentialId),
    ).resolves.toHaveLength(1);
  });
});

describe('the kind on an enrollment grant', () => {
  /** Register through the grant path at a route that passes no kind of its own. */
  async function redeem(auth: LocalWebAuthn, token: string, routeKind?: string) {
    const exchange = await auth.exchangeEnrollment(token);
    const { keyStore } = await generateKeyStore(ES256);
    const options = await auth.registrationOptions({
      enrollmentSessionToken: exchange.enrollmentSessionToken,
      credentialKind: routeKind,
    });
    const { response } = await createRegistrationResponse({
      keyStore,
      challenge: options.options.challenge,
      rpId: RP_ID,
      origin: ORIGIN,
    });
    return auth.verifyRegistration({
      response: response as unknown as RegistrationResponseJSON,
      challengeToken: options.challengeToken,
      enrollmentSessionToken: exchange.enrollmentSessionToken,
    });
  }

  it('confines the token to the class the issuer authorized', async () => {
    const { auth } = harness({ service: { interactive: false, canRegister: false } });
    const issue = await auth.issueEnrollment('user-1', { credentialKind: 'service' });

    // The token holder redeems it at the ordinary human route, which asks for no
    // kind. Before the grant carried one this produced kind:null — an
    // unrestricted credential, and a silent bypass of every restriction.
    const verified = await redeem(auth, issue.enrollmentToken);
    expect(verified.credentialKind).toBe('service');
    expect(auth.interactiveKind(verified.credentialKind)).toBe(false);
  });

  it('refuses a route that asks for a different class than the grant', async () => {
    const { auth } = harness({ service: { interactive: false } });
    const issue = await auth.issueEnrollment('user-1', { credentialKind: 'service' });
    // A host wiring two disagreeing sources is told, rather than having one win
    // silently.
    await expect(redeem(auth, issue.enrollmentToken, 'person')).rejects.toMatchObject({
      code: 'invalid_configuration',
    });
  });

  it('lets the route decide when the grant declares nothing', async () => {
    const { auth } = harness();
    const issue = await auth.issueEnrollment('user-1');
    const verified = await redeem(auth, issue.enrollmentToken, 'person');
    expect(verified.credentialKind).toBe('person');
  });

  it('keeps a pending grant of each kind alive side by side', async () => {
    const { auth } = harness({ service: { interactive: false } });
    const personGrant = await auth.issueEnrollment('user-1', { credentialKind: 'person' });
    const serviceGrant = await auth.issueEnrollment('user-1', { credentialKind: 'service' });

    // Provisioning a deployment key must not cancel the person's in-flight link.
    expect(serviceGrant.supersededGrantIds).toEqual([]);
    await expect(auth.exchangeEnrollment(personGrant.enrollmentToken)).resolves.toHaveProperty(
      'enrollmentSessionToken',
    );
  });

  it('still supersedes a pending grant of the same kind', async () => {
    const { auth } = harness();
    const first = await auth.issueEnrollment('user-1', { credentialKind: 'person' });
    const second = await auth.issueEnrollment('user-1', { credentialKind: 'person' });
    expect(second.supersededGrantIds).toEqual([first.grantId]);
    await expect(auth.exchangeEnrollment(first.enrollmentToken)).rejects.toMatchObject({
      code: 'invalid_enrollment',
    });
  });

  it('supersedes an unkinded grant with another unkinded one', async () => {
    // Unchanged behaviour for every host that never sets a kind: COALESCE makes
    // all-NULL grants one group, where a bare unique index would have made them
    // all distinct and silently dropped the invariant.
    const { auth } = harness();
    const first = await auth.issueEnrollment('user-1');
    const second = await auth.issueEnrollment('user-1');
    expect(second.supersededGrantIds).toEqual([first.grantId]);
  });
});

describe('kind-filtered revocation', () => {
  /** A person with one passkey and one API credential, each with a live session. */
  async function bothKinds() {
    const fixture = harness({ service: { interactive: false, canRegister: false } });
    const person = await bootstrap(fixture.auth, 'person', 'laptop');
    const service = await enroll(
      fixture.auth,
      person.verified.sessionToken,
      undefined,
      'service',
      'nightly export',
    );
    const credentials = await fixture.auth.listCredentials('user-1');
    const serviceCredential = credentials.find((credential) => credential.kind === 'service');
    // A second, independent service session, so counts are distinguishable.
    const extra = await assertOnce(
      fixture.auth,
      service.keyStore,
      {
        credentialId: service.credentialId,
        userHandle: fixture.user.webAuthnUserHandle,
        rpId: RP_ID,
        origin: ORIGIN,
      },
      ['service'],
    );
    return { ...fixture, person, service, serviceCredential, extra };
  }

  it('signs the person out without stopping the service credential', async () => {
    const { auth, person, extra } = await bothKinds();

    const count = await auth.revokeUserSessions('user-1', { kinds: ['person'] });
    expect(count).toBe(1);
    expect(await auth.resolveSession(person.verified.sessionToken)).toBeNull();
    // The nightly export keeps running.
    expect(await auth.resolveSession(extra.sessionToken)).not.toBeNull();
  });

  it('signs the service credential out without touching the person', async () => {
    const { auth, person, service, extra } = await bothKinds();

    const count = await auth.revokeUserSessions('user-1', { kinds: ['service'] });
    // Both service sessions: the one registration opened and the extra ceremony.
    expect(count).toBe(2);
    expect(await auth.resolveSession(person.verified.sessionToken)).not.toBeNull();
    expect(await auth.resolveSession(extra.sessionToken)).toBeNull();
    expect(await auth.resolveSession(service.verified.sessionToken)).toBeNull();
  });

  it('revokes machine credentials and leaves the passkeys', async () => {
    const { auth, person, serviceCredential } = await bothKinds();

    await auth.revokeUserAuthentication('user-1', { kinds: ['service'] });

    const active = await auth.listCredentials('user-1');
    expect(active).toHaveLength(1);
    expect(active[0].kind).toBe('person');
    const all = await auth.listCredentials('user-1', true);
    expect(all.find((c) => c.id === serviceCredential?.id)?.revokedAt).not.toBeNull();
    // The person is still signed in.
    expect(await auth.resolveSession(person.verified.sessionToken)).not.toBeNull();
  });

  it('revokes pending grants of the revoked kinds, and only those', async () => {
    const { auth } = await bothKinds();
    const personGrant = await auth.issueEnrollment('user-1', { credentialKind: 'person' });
    const serviceGrant = await auth.issueEnrollment('user-1', { credentialKind: 'service' });

    await auth.revokeUserAuthentication('user-1', { kinds: ['service'] });

    // A live service grant would be standing authorization to re-enroll straight
    // back in, undoing the revoke.
    await expect(auth.exchangeEnrollment(serviceGrant.enrollmentToken)).rejects.toMatchObject({
      code: 'invalid_enrollment',
    });
    // The person's in-flight link is untouched.
    await expect(auth.exchangeEnrollment(personGrant.enrollmentToken)).resolves.toHaveProperty(
      'enrollmentSessionToken',
    );
  });

  it('revokes every grant when unscoped', async () => {
    const { auth } = await bothKinds();
    const issue = await auth.issueEnrollment('user-1', { credentialKind: 'person' });
    await auth.revokeUserAuthentication('user-1');
    await expect(auth.exchangeEnrollment(issue.enrollmentToken)).rejects.toMatchObject({
      code: 'invalid_enrollment',
    });
  });

  /** A user whose every credential and grant shares one kind. */
  async function singleKind() {
    const fixture = harness();
    const first = await bootstrap(fixture.auth, 'person', 'laptop');
    const second = await enroll(
      fixture.auth,
      first.verified.sessionToken,
      undefined,
      'person',
      'phone',
    );
    const grant = await fixture.auth.issueEnrollment('user-1', { credentialKind: 'person' });
    return { ...fixture, first, second, grant };
  }

  type SingleKind = Awaited<ReturnType<typeof singleKind>>;

  function liveSessionCount(database: SingleKind['database']): number {
    return (
      database
        .prepare('SELECT COUNT(*) AS count FROM localwebauthn_sessions WHERE revoked_at IS NULL')
        .get() as { count: number }
    ).count;
  }

  /** Everything either revoke path is supposed to decide, by stable name. */
  async function state(fixture: SingleKind) {
    const credentials = await fixture.auth.listCredentials('user-1', true);
    return {
      first: (await fixture.auth.resolveSession(fixture.first.verified.sessionToken)) !== null,
      second: (await fixture.auth.resolveSession(fixture.second.verified.sessionToken)) !== null,
      liveSessions: liveSessionCount(fixture.database),
      active: credentials
        .filter((credential) => credential.revokedAt === null)
        .map((credential) => credential.label)
        .sort(),
      grantLive: await fixture.auth.exchangeEnrollment(fixture.grant.enrollmentToken).then(
        () => true,
        () => false,
      ),
    };
  }

  // Two implementations of one behaviour: the scoped paths loop per credential
  // because a variable-length kind filter cannot live in the shared static SQL,
  // while the unscoped paths are single statements. For a user with one kind the
  // two must be indistinguishable. This is the shape of assertion that would have
  // caught the scoped revoke leaving pending grants alive.
  it('agrees with the unscoped session revoke for a single-kind user', async () => {
    const scoped = await singleKind();
    const unscoped = await singleKind();

    const scopedCount = await scoped.auth.revokeUserSessions('user-1', { kinds: ['person'] });
    const unscopedCount = await unscoped.auth.revokeUserSessions('user-1');

    expect(scopedCount).toBe(unscopedCount);
    expect(await state(scoped)).toEqual(await state(unscoped));
  });

  it('agrees with the unscoped authentication revoke for a single-kind user', async () => {
    const scoped = await singleKind();
    const unscoped = await singleKind();

    await scoped.auth.revokeUserAuthentication('user-1', { kinds: ['person'] });
    await unscoped.auth.revokeUserAuthentication('user-1');

    // Unconsumed *challenges* are the one deliberate difference — the unscoped path
    // clears them, the scoped path leaves them, which is harmless because a
    // challenge whose credential or grant is revoked can no longer complete. This
    // fixture has none outstanding, so the two states must match exactly.
    expect(await state(scoped)).toEqual(await state(unscoped));
  });

  it('reports the scope on the event', async () => {
    const events: LocalWebAuthnEvent[] = [];
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
      onEvent: (event) => {
        events.push(event);
      },
    });
    await bootstrap(auth, 'person');

    await auth.revokeUserSessions('user-1', { kinds: ['person'] });
    await auth.revokeUserAuthentication('user-1', { kinds: ['person'] });

    expect(events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'user.sessions_revoked', kinds: ['person'] }),
        expect.objectContaining({ type: 'user.authentication_revoked', kinds: ['person'] }),
      ]),
    );
  });

  it('matches unclassified credentials with a null kind', async () => {
    const { auth } = harness();
    const legacy = await bootstrap(auth);
    expect(await auth.revokeUserSessions('user-1', { kinds: [null] })).toBe(1);
    expect(await auth.resolveSession(legacy.verified.sessionToken)).toBeNull();
  });

  it('is unchanged when no kinds are given', async () => {
    const { auth, person, extra } = await bothKinds();
    expect(await auth.revokeUserSessions('user-1')).toBe(3);
    expect(await auth.resolveSession(person.verified.sessionToken)).toBeNull();
    expect(await auth.resolveSession(extra.sessionToken)).toBeNull();
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

  it('refuses DPoP when the store implements only the required contract', async () => {
    const database = new Database(':memory:');
    migrateSqlite(database);
    const complete = new SqliteLocalWebAuthnStore(database);
    // A custom store that implements LocalWebAuthnStore and nothing else, which is
    // legal: the three DPoP methods are a separate optional contract, so a host
    // with no API credentials writes none of them. Bound to the real instance
    // because its methods reach private fields.
    const store = new Proxy(complete, {
      get(target, property) {
        if (property === 'claimDpopProof' || property === 'claimDpopNonce') {
          return undefined;
        }
        const value: unknown = Reflect.get(target, property, target);
        return typeof value === 'function'
          ? (value as (...args: unknown[]) => unknown).bind(target)
          : value;
      },
    }) as LocalWebAuthnStore;

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
      store,
      users: { getUser: async (id) => (id === user.id ? user : null) },
      dpopNonce: { rotationMs: 60_000 },
    });

    // Both DPoP entry points name what is missing, and only those two — this store
    // still has `dpopNonces`, so the message must not claim otherwise.
    await expect(auth.dpopNonce()).rejects.toMatchObject({ code: 'invalid_configuration' });
    // Names what is missing, and only that — this store still has `dpopNonces`.
    await expect(auth.dpopNonce()).rejects.toThrow(/missing claimDpopProof, claimDpopNonce\.$/u);
    // A synthetic session is enough precisely because the check runs before any
    // verification work: a misconfigured store is reported as such whether or not
    // the proof would have passed.
    await expect(
      auth.verifyDpop({
        proof: 'not.a.proof',
        method: 'GET',
        url: `${ORIGIN}/api/machine/v1/whoami`,
        sessionToken: 'token',
        session: { credentialId: 'credential-1', credentialKind: 'service' } as SessionIdentity,
      }),
    ).rejects.toMatchObject({ code: 'invalid_configuration' });

    // Everything else about the store still works, so the split costs a host that
    // does not use DPoP nothing at all.
    await expect(auth.issueEnrollment('user-1')).resolves.toHaveProperty('enrollmentToken');
    database.close();
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
