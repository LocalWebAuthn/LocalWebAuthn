/**
 * The API-key flow over real HTTP, end to end.
 *
 * A person signs in with a software Passkey, mints an API credential through the
 * browser-facing routes, and then a `MachineClient` built from the resulting
 * `.env` payload calls the script-facing routes with DPoP proofs. Every request
 * goes through the demo's actual Hono app, including its origin-check middleware.
 */

import { describe, expect, it } from 'vitest';

import type { CredentialPayload } from '@localwebauthn/client';
import {
  createAssertionResponse,
  createRegistrationResponse,
  encodeBase64Url,
  ES256,
  generateKeyStore,
  importKeyStore,
  MachineClient,
  type MachineKeyStore,
  type SoftwareCredential,
} from '@localwebauthn/client';
import { createUserHandle } from '@localwebauthn/server';
import { randomUUID } from 'node:crypto';

import { createDemoApplication } from '../src/application';
import { openDemoDatabase } from '../src/database';

const ORIGIN = 'http://localhost:4173';
const RP_ID = 'localhost';

function setup() {
  const database = openDemoDatabase(':memory:');
  const application = createDemoApplication(database, {
    auth: { publicOrigin: ORIGIN, rpId: RP_ID, rpName: 'LocalWebAuthn Test' },
  });
  return { database, ...application };
}

/** A `fetch` bound to the app, so `MachineClient` can drive it without a socket. */
function appFetch(app: ReturnType<typeof setup>['app']): typeof globalThis.fetch {
  return async (input, init) => app.fetch(new Request(input, init));
}

function post(path: string, body: unknown, cookie?: string): Request {
  return new Request(`${ORIGIN}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Origin: ORIGIN,
      ...(cookie ? { Cookie: cookie } : {}),
    },
    body: JSON.stringify(body ?? {}),
  });
}

function sessionCookie(response: Response): string {
  const header = response.headers.get('Set-Cookie') ?? '';
  const match = /(?<pair>lwa_demo_session=[^;]+)/u.exec(header);
  return match?.groups?.pair ?? '';
}

/** Create a person with a real software Passkey, and sign them in. */
async function signedInPerson(fixture: ReturnType<typeof setup>): Promise<{
  userId: string;
  cookie: string;
  keyStore: MachineKeyStore;
  credential: SoftwareCredential;
}> {
  const { database, app, authentication } = fixture;
  const userId = randomUUID();
  const userHandle = createUserHandle();
  database
    .prepare(
      `INSERT INTO demo_clients(
         id, email, display_name, role, webauthn_user_handle, created_at
       ) VALUES (?, ?, ?, 'administrator', ?, ?)`,
    )
    .run(userId, `${userId}@example.test`, 'A Person', Buffer.from(userHandle), Date.now());

  // Enrol the person's own passkey through the grant path.
  const issue = await authentication.issueEnrollment(userId);
  const exchange = await authentication.exchangeEnrollment(issue.enrollmentToken);
  const { keyStore } = await generateKeyStore(ES256);
  const options = await authentication.registrationOptions({
    enrollmentSessionToken: exchange.enrollmentSessionToken,
  });
  const registration = await createRegistrationResponse({
    keyStore,
    challenge: options.options.challenge,
    rpId: RP_ID,
    origin: ORIGIN,
  });
  await authentication.verifyRegistration({
    response: registration.response as never,
    challengeToken: options.challengeToken,
    enrollmentSessionToken: exchange.enrollmentSessionToken,
    label: 'A Person laptop',
  });

  const credential: SoftwareCredential = {
    credentialId: registration.credentialId,
    userHandle,
    rpId: RP_ID,
    origin: ORIGIN,
  };

  // Sign in over HTTP so the browser cookie is real.
  const loginOptions = await app.fetch(post('/api/auth/login/options', {}));
  const challengeCookie = /(?<pair>lwa_demo_challenge=[^;]+)/u.exec(
    loginOptions.headers.get('Set-Cookie') ?? '',
  )?.groups?.pair;
  const assertion = await createAssertionResponse({
    keyStore,
    credential,
    challenge: ((await loginOptions.json()) as { challenge: string }).challenge,
  });
  const verified = await app.fetch(post('/api/auth/login/verify', assertion, challengeCookie));
  expect(verified.status).toBe(200);

  return { userId, cookie: sessionCookie(verified), keyStore, credential };
}

/** Mint an API credential the way the browser page does. */
async function mintApiKey(
  fixture: ReturnType<typeof setup>,
  cookie: string,
  label: string,
): Promise<{ payload: CredentialPayload; privateKey: string }> {
  const { app } = fixture;
  const optionsResponse = await app.fetch(post('/api/api-keys/options', {}, cookie));
  expect(optionsResponse.status).toBe(200);
  const { options, challengeToken } = (await optionsResponse.json()) as {
    options: { challenge: string; user: { id: string } };
    challengeToken: string;
  };

  // The page generates the key pair itself; the private half never leaves it.
  const { keyStore, exportPrivateKey } = await generateKeyStore(ES256);
  const registration = await createRegistrationResponse({
    keyStore,
    challenge: options.challenge,
    rpId: RP_ID,
    origin: ORIGIN,
  });
  const verifyResponse = await app.fetch(
    post(
      '/api/api-keys/verify',
      { response: registration.response, challengeToken, label },
      cookie,
    ),
  );
  expect(verifyResponse.status).toBe(201);
  const { credentialKind } = (await verifyResponse.json()) as { credentialKind: string };
  expect(credentialKind).toBe('service');

  return {
    privateKey: await exportPrivateKey(),
    payload: {
      v: 1,
      baseUrl: ORIGIN,
      rpId: RP_ID,
      origin: ORIGIN,
      credentialId: encodeBase64Url(registration.credentialId),
      userHandle: options.user.id,
      alg: ES256,
    },
  };
}

describe('issuing an API credential', () => {
  it('mints one, and the script authenticates with DPoP', async () => {
    const fixture = setup();
    const person = await signedInPerson(fixture);
    const { payload, privateKey } = await mintApiKey(fixture, person.cookie, 'nightly export');

    const client = new MachineClient({
      payload,
      keyStore: await importKeyStore(privateKey, ES256),
      fetch: appFetch(fixture.app),
    });

    const whoami = await client.fetch('/api/machine/v1/whoami');
    expect(whoami.status).toBe(200);
    expect(await whoami.json()).toMatchObject({
      userId: person.userId,
      credentialKind: 'service',
    });

    const clients = await client.fetch('/api/machine/v1/clients');
    expect(clients.status).toBe(200);
    expect((await clients.json()) as { clients: unknown[] }).toHaveProperty('clients');
  });

  it('lists the API credential separately from the person passkey', async () => {
    const fixture = setup();
    const person = await signedInPerson(fixture);
    await mintApiKey(fixture, person.cookie, 'nightly export');

    const response = await fixture.app.fetch(
      new Request(`${ORIGIN}/api/api-keys`, { headers: { Cookie: person.cookie } }),
    );
    const { apiKeys } = (await response.json()) as { apiKeys: { label: string }[] };
    expect(apiKeys).toHaveLength(1);
    expect(apiKeys[0].label).toBe('nightly export');

    // The person's own passkey is not in that list.
    const credentials = await fixture.authentication.listCredentials(person.userId);
    expect(credentials).toHaveLength(2);
    expect(credentials.filter((credential) => credential.kind === null)).toHaveLength(1);
  });

  it('keeps the API credential out of the person passkey list', async () => {
    const fixture = setup();
    const person = await signedInPerson(fixture);
    await mintApiKey(fixture, person.cookie, 'nightly export');

    // Rendering it under "Passkeys" would show it as "Device-bound", which is
    // precisely the mislabelling `kind` exists to prevent — and would offer a
    // revoke button under the wrong heading.
    const response = await fixture.app.fetch(
      new Request(`${ORIGIN}/api/session`, { headers: { Cookie: person.cookie } }),
    );
    const body = (await response.json()) as {
      passkeys: { label: string }[];
      client: { passkeyCount: number };
    };
    expect(body.passkeys.map((passkey) => passkey.label)).toEqual(['A Person laptop']);
    // The administrator table's count means "can sign in", so it excludes it too.
    expect(body.client.passkeyCount).toBe(1);
  });

  it('refuses to mint without a session', async () => {
    const fixture = setup();
    const response = await fixture.app.fetch(post('/api/api-keys/options', {}));
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: 'unauthenticated' });
  });

  it('revokes an API credential without touching the person passkey', async () => {
    const fixture = setup();
    const person = await signedInPerson(fixture);
    const { payload, privateKey } = await mintApiKey(fixture, person.cookie, 'nightly export');
    const client = new MachineClient({
      payload,
      keyStore: await importKeyStore(privateKey, ES256),
      fetch: appFetch(fixture.app),
    });
    expect((await client.fetch('/api/machine/v1/whoami')).status).toBe(200);

    const revoked = await fixture.app.fetch(
      post(`/api/api-keys/${payload.credentialId}/revoke`, {}, person.cookie),
    );
    expect(revoked.status).toBe(200);

    // A fresh client cannot authenticate at all now.
    const afterRevoke = new MachineClient({
      payload,
      keyStore: await importKeyStore(privateKey, ES256),
      fetch: appFetch(fixture.app),
    });
    await expect(afterRevoke.fetch('/api/machine/v1/whoami')).rejects.toMatchObject({
      code: 'authentication_failed',
    });

    // The person is still signed in.
    const session = await fixture.app.fetch(
      new Request(`${ORIGIN}/api/session`, { headers: { Cookie: person.cookie } }),
    );
    expect(session.status).toBe(200);
  });
});

describe('the origin-check exemption', () => {
  /** Machine routes are declared cookie-free, so no `Origin` is required. */
  it('lets a machine route through with no Origin header', async () => {
    const fixture = setup();
    const response = await fixture.app.fetch(
      new Request(`${ORIGIN}/api/machine/v1/login/options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      }),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
  });

  it('still rejects a cookie route with no Origin', async () => {
    const fixture = setup();
    const response = await fixture.app.fetch(
      new Request(`${ORIGIN}/api/auth/login/options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      }),
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: 'invalid_origin' });
  });

  it('still rejects a cookie route with a foreign Origin', async () => {
    const fixture = setup();
    const response = await fixture.app.fetch(
      new Request(`${ORIGIN}/api/auth/login/options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' },
        body: '{}',
      }),
    );
    expect(response.status).toBe(403);
  });

  it('does not let a traversal path claim the exemption', async () => {
    const fixture = setup();
    // The exemption is decided on the normalized path, so `/api/machine/..` cannot
    // be used to reach a cookie route without an Origin header.
    const response = await fixture.app.fetch(
      new Request(`${ORIGIN}/api/machine/../auth/login/options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      }),
    );
    expect(response.status).toBe(403);
  });

  it('registration order no longer matters for the exemption', async () => {
    // Machine routes are now mounted *after* the middleware, which previously
    // would have subjected them to the origin check.
    const fixture = setup();
    const person = await signedInPerson(fixture);
    const { payload, privateKey } = await mintApiKey(fixture, person.cookie, 'nightly export');
    const client = new MachineClient({
      payload,
      keyStore: await importKeyStore(privateKey, ES256),
      // A plain fetch that sets no Origin, exactly as a script would.
      fetch: appFetch(fixture.app),
    });
    expect((await client.fetch('/api/machine/v1/whoami')).status).toBe(200);
  });
});

describe('restrictions enforced over HTTP', () => {
  it('refuses a person passkey at the machine login route', async () => {
    const fixture = setup();
    const person = await signedInPerson(fixture);

    const optionsResponse = await fixture.app.fetch(post('/api/machine/v1/login/options', {}));
    const { options, challengeToken } = (await optionsResponse.json()) as {
      options: { challenge: string };
      challengeToken: string;
    };
    const assertion = await createAssertionResponse({
      keyStore: person.keyStore,
      credential: person.credential,
      challenge: options.challenge,
    });
    const verify = await fixture.app.fetch(
      post('/api/machine/v1/login/verify', { response: assertion, challengeToken }),
    );
    expect(verify.status).toBe(401);
  });

  it('refuses a service credential at the browser login route', async () => {
    const fixture = setup();
    const person = await signedInPerson(fixture);
    const { payload, privateKey } = await mintApiKey(fixture, person.cookie, 'nightly export');
    const keyStore = await importKeyStore(privateKey, ES256);

    const loginOptions = await fixture.app.fetch(post('/api/auth/login/options', {}));
    const challengeCookie = /(?<pair>lwa_demo_challenge=[^;]+)/u.exec(
      loginOptions.headers.get('Set-Cookie') ?? '',
    )?.groups?.pair;
    const assertion = await createAssertionResponse({
      keyStore,
      credential: {
        credentialId: (await import('@localwebauthn/client')).decodeBase64Url(payload.credentialId),
        userHandle: (await import('@localwebauthn/client')).decodeBase64Url(payload.userHandle),
        rpId: RP_ID,
        origin: ORIGIN,
      },
      challenge: ((await loginOptions.json()) as { challenge: string }).challenge,
    });
    const verified = await fixture.app.fetch(
      post('/api/auth/login/verify', assertion, challengeCookie),
    );
    expect(verified.status).toBe(401);
  });

  it('rejects a machine request with no DPoP proof', async () => {
    const fixture = setup();
    const person = await signedInPerson(fixture);
    const { payload, privateKey } = await mintApiKey(fixture, person.cookie, 'nightly export');

    // `dpop: false` sends a bare Bearer token, which the machine middleware
    // refuses: the sender-constraint is the point.
    const client = new MachineClient({
      payload,
      keyStore: await importKeyStore(privateKey, ES256),
      fetch: appFetch(fixture.app),
      dpop: false,
    });
    const response = await client.fetch('/api/machine/v1/whoami');
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: 'invalid_dpop_proof' });
  });

  it('challenges a nonce-less proof and accepts the retry', async () => {
    const fixture = setup();
    const person = await signedInPerson(fixture);
    const { payload, privateKey } = await mintApiKey(fixture, person.cookie, 'nightly export');
    const keyStore = await importKeyStore(privateKey, ES256);
    const client = new MachineClient({ payload, keyStore, fetch: appFetch(fixture.app) });
    const session = await client.authenticate();
    const { createDpopProof } = await import('@localwebauthn/client');

    // First attempt carries no nonce, because the client has not been told one.
    const bare = await fixture.app.fetch(
      new Request(`${ORIGIN}/api/machine/v1/whoami`, {
        headers: {
          Authorization: `DPoP ${session.token}`,
          DPoP: await createDpopProof({
            keyStore,
            method: 'GET',
            url: `${ORIGIN}/api/machine/v1/whoami`,
            accessToken: session.token,
          }),
        },
      }),
    );
    expect(bare.status).toBe(401);
    expect(await bare.json()).toMatchObject({ error: 'dpop_nonce_required' });
    expect(bare.headers.get('WWW-Authenticate')).toBe('DPoP error="use_dpop_nonce"');
    const nonce = bare.headers.get('DPoP-Nonce');
    expect(nonce).toBeTruthy();

    // Retry with the nonce the challenge supplied.
    const retried = await fixture.app.fetch(
      new Request(`${ORIGIN}/api/machine/v1/whoami`, {
        headers: {
          Authorization: `DPoP ${session.token}`,
          DPoP: await createDpopProof({
            keyStore,
            method: 'GET',
            url: `${ORIGIN}/api/machine/v1/whoami`,
            accessToken: session.token,
            nonce: nonce ?? undefined,
          }),
        },
      }),
    );
    expect(retried.status).toBe(200);
  });

  it('handles the nonce challenge transparently in MachineClient', async () => {
    const fixture = setup();
    const person = await signedInPerson(fixture);
    const { payload, privateKey } = await mintApiKey(fixture, person.cookie, 'nightly export');
    const client = new MachineClient({
      payload,
      keyStore: await importKeyStore(privateKey, ES256),
      fetch: appFetch(fixture.app),
    });

    // The very first call has no nonce to offer, so it takes the 401 + retry path
    // without the caller seeing it — and the session survives, since a nonce
    // challenge is not an expiry.
    const first = await client.fetch('/api/machine/v1/whoami');
    expect(first.status).toBe(200);
    const second = await client.fetch('/api/machine/v1/clients');
    expect(second.status).toBe(200);
  });

  it('rejects a replayed DPoP proof', async () => {
    const fixture = setup();
    const person = await signedInPerson(fixture);
    const { payload, privateKey } = await mintApiKey(fixture, person.cookie, 'nightly export');
    const keyStore = await importKeyStore(privateKey, ES256);
    const client = new MachineClient({ payload, keyStore, fetch: appFetch(fixture.app) });

    const first = await client.fetch('/api/machine/v1/whoami');
    expect(first.status).toBe(200);
    // The server rotates the client onto the current nonce on every success.
    const nonce = first.headers.get('DPoP-Nonce');
    expect(nonce).toBeTruthy();

    // Build two proofs by hand that share a nonce but differ in jti. The nonce is
    // reusable by design — it only has to be unguessable in advance — while the
    // jti is single-use. The two mechanisms are independent, and this is what
    // proves it: reusing the nonce is fine, reusing the jti is not.
    const session = await client.authenticate();
    const { createDpopProof } = await import('@localwebauthn/client');
    const proofFor = () =>
      createDpopProof({
        keyStore,
        method: 'GET',
        url: `${ORIGIN}/api/machine/v1/whoami`,
        accessToken: session.token,
        nonce: nonce ?? undefined,
      });

    const fresh = await proofFor();
    expect(
      (
        await fixture.app.fetch(
          new Request(`${ORIGIN}/api/machine/v1/whoami`, {
            headers: { Authorization: `DPoP ${session.token}`, DPoP: await proofFor() },
          }),
        )
      ).status,
    ).toBe(200);

    const headers = { Authorization: `DPoP ${session.token}`, DPoP: fresh };
    const replayFirst = await fixture.app.fetch(
      new Request(`${ORIGIN}/api/machine/v1/whoami`, { headers }),
    );
    expect(replayFirst.status).toBe(200);
    const replaySecond = await fixture.app.fetch(
      new Request(`${ORIGIN}/api/machine/v1/whoami`, { headers }),
    );
    expect(replaySecond.status).toBe(401);
    expect(await replaySecond.json()).toMatchObject({ error: 'invalid_dpop_proof' });
  });

  it('stops a service session from minting another credential', async () => {
    const fixture = setup();
    const person = await signedInPerson(fixture);
    const { payload, privateKey } = await mintApiKey(fixture, person.cookie, 'nightly export');
    const client = new MachineClient({
      payload,
      keyStore: await importKeyStore(privateKey, ES256),
      fetch: appFetch(fixture.app),
    });
    const session = await client.authenticate();

    // Even presented as a cookie, a service session cannot reach the registration
    // path: the package refuses it, and the demo route requires a person anyway.
    const response = await fixture.app.fetch(
      post('/api/api-keys/options', {}, `lwa_demo_session=${session.token}`),
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: 'forbidden' });
  });
});

describe('a machine session cannot escalate through the grant path', () => {
  /**
   * Regression test for a real hole.
   *
   * `canRegister: false` gates the *session* registration path. The *grant* path
   * is a second route to registration, gated only by possession of a single-use
   * enrollment token — it has no authorizing session, so the package cannot apply
   * `canRegister` there at all. The chain that mattered:
   *
   *   machine session token -> presented as a Cookie -> /api/clients/:id/enrollment
   *   -> enrollment token -> exchange -> registrationOptions({ enrollmentSessionToken })
   *   -> a brand new credential, with canRegister:false fully bypassed.
   *
   * The fix is host-side and has to be, since only the host knows who is calling
   * `issueEnrollment`: `requireAuthentication` refuses a non-interactive kind.
   */
  async function machineSession(fixture: ReturnType<typeof setup>, cookie: string) {
    const { payload, privateKey } = await mintApiKey(fixture, cookie, 'nightly export');
    const client = new MachineClient({
      payload,
      keyStore: await importKeyStore(privateKey, ES256),
      fetch: appFetch(fixture.app),
    });
    return (await client.authenticate()).token;
  }

  it('cannot mint an enrollment grant', async () => {
    const fixture = setup();
    const person = await signedInPerson(fixture);
    const token = await machineSession(fixture, person.cookie);

    // A script sets Cookie and Origin freely; only the credential kind stops it.
    const response = await fixture.app.fetch(
      post(`/api/clients/${person.userId}/enrollment`, {}, `lwa_demo_session=${token}`),
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: 'forbidden' });
  });

  it('cannot reach any other privileged browser route', async () => {
    const fixture = setup();
    const person = await signedInPerson(fixture);
    const token = await machineSession(fixture, person.cookie);
    const cookie = `lwa_demo_session=${token}`;

    // One middleware guards them all, so this stays true for routes added later.
    for (const path of ['/api/session', '/api/clients', '/api/api-keys']) {
      const response = await fixture.app.fetch(
        new Request(`${ORIGIN}${path}`, { headers: { Cookie: cookie } }),
      );
      expect(response.status).toBe(403);
    }
    for (const path of ['/api/session/revoke-others', '/api/clients']) {
      expect((await fixture.app.fetch(post(path, {}, cookie))).status).toBe(403);
    }
  });

  it('still lets the person through those routes', async () => {
    const fixture = setup();
    const person = await signedInPerson(fixture);
    expect(
      (
        await fixture.app.fetch(
          new Request(`${ORIGIN}/api/session`, { headers: { Cookie: person.cookie } }),
        )
      ).status,
    ).toBe(200);
    expect(
      (await fixture.app.fetch(post(`/api/clients/${person.userId}/enrollment`, {}, person.cookie)))
        .status,
    ).toBe(200);
  });
});
