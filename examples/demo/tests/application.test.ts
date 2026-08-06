import { afterEach, describe, expect, it } from 'vitest';

import type { DemoDatabase, DemoRole } from '../src/database';

import { createOpaqueToken, createUserHandle, sha256 } from '@localwebauthn/server';
import { randomUUID } from 'node:crypto';

import { createDemoApplication, ensureBootstrapAdministrator } from '../src/application';
import { openDemoDatabase } from '../src/database';

const publicOrigin = 'http://localhost:4173';
const databases: DemoDatabase[] = [];

function setup() {
  const database = openDemoDatabase(':memory:');
  databases.push(database);
  const application = createDemoApplication(database, {
    auth: {
      publicOrigin,
      rpId: 'localhost',
      rpName: 'LocalWebAuthn Test',
    },
  });
  return { database, ...application };
}

async function authenticatedClient(
  database: DemoDatabase,
  role: DemoRole,
): Promise<{ id: string; cookie: string }> {
  const id = randomUUID();
  const credentialId = `credential-${id}`;
  const sessionToken = createOpaqueToken();
  const now = Date.now();
  database
    .prepare(
      `INSERT INTO demo_clients(
         id, email, display_name, role, webauthn_user_handle, created_at
       ) VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .run(id, `${role}-${id}@example.test`, `${role} client`, role, createUserHandle(), now);
  database
    .prepare(
      `INSERT INTO localwebauthn_credentials(
         id, user_id, public_key, counter, transports_json,
         device_type, backed_up, label, created_at
       ) VALUES (?, ?, ?, 0, '[]', 'singleDevice', 0, 'Test passkey', ?)`,
    )
    .run(credentialId, id, Buffer.from('test-public-key'), now);
  database
    .prepare(
      `INSERT INTO localwebauthn_sessions(
         id_hash, user_id, credential_id,
         authenticated_at, expires_at, last_seen_at
       ) VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .run(await sha256(sessionToken), id, credentialId, now, now + 60_000, now);
  return {
    id,
    // Matches authCookieNames(publicOrigin, 'lwa_demo') on local HTTP.
    cookie: `lwa_demo_session=${sessionToken}`,
  };
}

/** A second live session for an existing client (another device). */
async function additionalSession(database: DemoDatabase, userId: string): Promise<string> {
  const sessionToken = createOpaqueToken();
  const now = Date.now();
  const credential = database
    .prepare(`SELECT id FROM localwebauthn_credentials WHERE user_id = ?`)
    .get(userId) as { id: string };
  database
    .prepare(
      `INSERT INTO localwebauthn_sessions(
         id_hash, user_id, credential_id,
         authenticated_at, expires_at, last_seen_at
       ) VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .run(await sha256(sessionToken), userId, credential.id, now, now + 60_000, now);
  return sessionToken;
}

afterEach(() => {
  for (const database of databases.splice(0)) {
    database.close();
  }
});

describe('LocalWebAuthn demo application', () => {
  it('creates and exchanges the initial administrator bootstrap URL once', async () => {
    const { app, authentication, database } = setup();
    const bootstrap = await ensureBootstrapAdministrator(database, authentication, {
      email: 'admin@example.test',
      displayName: 'Demo Administrator',
    });
    expect(bootstrap?.enrollmentUrl).toMatch(
      /^http:\/\/localhost:4173\/enroll#token=[a-z2-7]{52}$/u,
    );
    if (!bootstrap) {
      throw new Error('The bootstrap enrollment was not created.');
    }
    const token = new URL(bootstrap.enrollmentUrl).hash.slice('#token='.length);
    const exchanged = await app.request('/api/auth/enrollment/exchange', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: publicOrigin,
      },
      body: JSON.stringify({ token }),
    });
    expect(exchanged.status).toBe(200);
    await expect(exchanged.json()).resolves.toMatchObject({
      name: 'admin@example.test',
      displayName: 'Demo Administrator',
    });
    expect(exchanged.headers.get('set-cookie')).toContain('lwa_demo_enrollment=');

    const replay = await app.request('/api/auth/enrollment/exchange', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: publicOrigin,
      },
      body: JSON.stringify({ token }),
    });
    expect(replay.status).toBe(403);
  });

  it('lets an administrator create clients and issue enrollment URLs', async () => {
    const { app, database } = setup();
    const administrator = await authenticatedClient(database, 'administrator');
    const headers = {
      Cookie: administrator.cookie,
      Origin: publicOrigin,
      'Content-Type': 'application/json',
    };

    const created = await app.request('/api/clients', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        displayName: 'Ada Client',
        email: 'ada@example.test',
      }),
    });
    expect(created.status).toBe(201);
    const result = (await created.json()) as {
      client: { id: string; email: string; passkeyCount: number };
      enrollmentUrl: string;
    };
    expect(result.client).toMatchObject({
      email: 'ada@example.test',
      passkeyCount: 0,
    });
    expect(result.enrollmentUrl).toMatch(/^http:\/\/localhost:4173\/enroll#token=[a-z2-7]{52}$/u);

    const replacement = await app.request(`/api/clients/${result.client.id}/enrollment`, {
      method: 'POST',
      headers,
    });
    expect(replacement.status).toBe(200);
    const replacementPayload = (await replacement.json()) as unknown as {
      enrollmentUrl: string;
    };
    expect(replacementPayload.enrollmentUrl).not.toBe(result.enrollmentUrl);

    const options = await app.request('/api/auth/register/options', {
      method: 'POST',
      headers,
    });
    expect(options.status).toBe(200);
    const optionsPayload = (await options.json()) as unknown as {
      rp: { id: string; name: string };
      user: { id: unknown };
    };
    expect(optionsPayload.rp).toEqual({ id: 'localhost', name: 'LocalWebAuthn Test' });
    expect(typeof optionsPayload.user.id).toBe('string');
    expect(options.headers.get('set-cookie')).toContain('lwa_demo_challenge=');
  });

  it('keeps client creation restricted to administrators', async () => {
    const { app, database } = setup();
    const client = await authenticatedClient(database, 'client');
    const response = await app.request('/api/clients', {
      method: 'POST',
      headers: {
        Cookie: client.cookie,
        Origin: publicOrigin,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        displayName: 'Blocked Client',
        email: 'blocked@example.test',
      }),
    });
    expect(response.status).toBe(403);
  });

  it('lets an administrator end sessions while passkeys stay valid', async () => {
    const { app, database } = setup();
    const administrator = await authenticatedClient(database, 'administrator');
    const subject = await authenticatedClient(database, 'client');
    const headers = { Cookie: administrator.cookie, Origin: publicOrigin };

    // Administrator-only, like the other client actions.
    const forbidden = await app.request(`/api/clients/${administrator.id}/revoke-sessions`, {
      method: 'POST',
      headers: { Cookie: subject.cookie, Origin: publicOrigin },
    });
    expect(forbidden.status).toBe(403);

    const missing = await app.request('/api/clients/unknown-client/revoke-sessions', {
      method: 'POST',
      headers,
    });
    expect(missing.status).toBe(404);

    const response = await app.request(`/api/clients/${subject.id}/revoke-sessions`, {
      method: 'POST',
      headers,
    });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      revokedSessions: 1,
      client: { passkeyCount: 1 },
    });

    // The subject's session is dead, but their passkey survived.
    const oldSession = await app.request('/api/session', {
      headers: { Cookie: subject.cookie, Origin: publicOrigin },
    });
    expect(oldSession.status).toBe(401);
  });

  it('signs out other sessions while keeping the caller signed in', async () => {
    const { app, database } = setup();
    const subject = await authenticatedClient(database, 'client');
    const otherToken = await additionalSession(database, subject.id);

    const unauthenticated = await app.request('/api/session/revoke-others', {
      method: 'POST',
      headers: { Origin: publicOrigin },
    });
    expect(unauthenticated.status).toBe(401);

    const response = await app.request('/api/session/revoke-others', {
      method: 'POST',
      headers: { Cookie: subject.cookie, Origin: publicOrigin },
    });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ revokedSessions: 1 });

    // The caller's own session survives; the other device is signed out.
    const own = await app.request('/api/session', {
      headers: { Cookie: subject.cookie, Origin: publicOrigin },
    });
    expect(own.status).toBe(200);
    const other = await app.request('/api/session', {
      headers: { Cookie: `lwa_demo_session=${otherToken}`, Origin: publicOrigin },
    });
    expect(other.status).toBe(401);
  });

  it('runs simulated self-serve signup: proofs, claim-on-reopen, working enrollment', async () => {
    const { app } = setup();
    const headers = { Origin: publicOrigin, 'Content-Type': 'application/json' };

    const started = await app.request('/api/signup/start', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        displayName: 'Ada Self',
        email: 'self@example.test',
        phone: '+15551230000',
      }),
    });
    expect(started.status).toBe(201);
    const startPayload = (await started.json()) as {
      signupId: string;
      recovery: boolean;
      simulated: { channel: string; body: string }[];
    };
    expect(startPayload.recovery).toBe(false);

    // Proof links are capability-free: no enrollment token exists yet.
    const otps: Record<string, string> = {};
    for (const message of startPayload.simulated) {
      expect(message.body).toContain('/signup#signup=');
      expect(message.body).not.toContain('enroll#token');
      const url = new URL(/https?:\/\/\S+/u.exec(message.body)?.[0] ?? '');
      const fragment = new URLSearchParams(url.hash.slice(1));
      otps[fragment.get('channel') ?? ''] = fragment.get('otp') ?? '';
    }
    expect(Object.keys(otps).sort()).toEqual(['email', 'phone']);

    const prove = (channel: string, otp: string) =>
      app.request('/api/signup/prove', {
        method: 'POST',
        headers,
        body: JSON.stringify({ signupId: startPayload.signupId, channel, otp }),
      });

    expect((await prove('email', 'wrong-otp')).status).toBe(403);

    const first = await prove('email', otps.email);
    expect(first.status).toBe(200);
    const firstPayload = (await first.json()) as Record<string, unknown>;
    expect(firstPayload).toMatchObject({ complete: false, missing: ['phone'] });
    expect(firstPayload).not.toHaveProperty('enrollmentToken');

    // Re-presenting the same OTP pre-completion is the polling signal.
    await expect((await prove('email', otps.email)).json()).resolves.toMatchObject({
      complete: false,
      missing: ['phone'],
    });

    const second = await prove('phone', otps.phone);
    const secondPayload = (await second.json()) as { complete: boolean; enrollmentToken: string };
    expect(secondPayload.complete).toBe(true);
    expect(secondPayload.enrollmentToken).toMatch(/^[a-z2-7]{52}$/u);

    // Claim-on-reopen: the other channel's OTP now claims the same enrollment.
    await expect((await prove('email', otps.email)).json()).resolves.toMatchObject({
      complete: true,
      enrollmentToken: secondPayload.enrollmentToken,
    });

    // The token is a real, working enrollment.
    const exchanged = await app.request('/api/auth/enrollment/exchange', {
      method: 'POST',
      headers,
      body: JSON.stringify({ token: secondPayload.enrollmentToken }),
    });
    expect(exchanged.status).toBe(200);
  });

  it('self-serve recovery re-proofs both channels for clients and refuses administrators', async () => {
    const { app, database } = setup();
    const subject = await authenticatedClient(database, 'client');
    const administrator = await authenticatedClient(database, 'administrator');
    const headers = { Origin: publicOrigin, 'Content-Type': 'application/json' };

    const started = await app.request('/api/signup/start', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        displayName: 'Ignored For Recovery',
        email: `client-${subject.id}@example.test`,
        phone: '+15551230001',
      }),
    });
    const startPayload = (await started.json()) as {
      signupId: string;
      recovery: boolean;
      simulated: { body: string }[];
    };
    expect(startPayload.recovery).toBe(true);

    const otps: Record<string, string> = {};
    for (const message of startPayload.simulated) {
      const url = new URL(/https?:\/\/\S+/u.exec(message.body)?.[0] ?? '');
      const fragment = new URLSearchParams(url.hash.slice(1));
      otps[fragment.get('channel') ?? ''] = fragment.get('otp') ?? '';
    }
    for (const channel of ['email', 'phone']) {
      const response = await app.request('/api/signup/prove', {
        method: 'POST',
        headers,
        body: JSON.stringify({ signupId: startPayload.signupId, channel, otp: otps[channel] }),
      });
      expect(response.status).toBe(200);
    }

    // Recovery revoked the old credentials and sessions before issuing.
    const oldSession = await app.request('/api/session', {
      headers: { Cookie: subject.cookie, Origin: publicOrigin },
    });
    expect(oldSession.status).toBe(401);

    // Administrator accounts are not self-serve recoverable.
    const adminStart = await app.request('/api/signup/start', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        displayName: 'Nope',
        email: `administrator-${administrator.id}@example.test`,
        phone: '+15551230002',
      }),
    });
    expect(adminStart.status).toBe(409);
  });

  it('re-enrolls by revoking then issuing a recovery link', async () => {
    const { app, database } = setup();
    const administrator = await authenticatedClient(database, 'administrator');
    const subject = await authenticatedClient(database, 'client');
    const headers = {
      Cookie: administrator.cookie,
      Origin: publicOrigin,
      'Content-Type': 'application/json',
    };

    const recovery = await app.request(`/api/clients/${subject.id}/re-enroll`, {
      method: 'POST',
      headers,
    });
    expect(recovery.status).toBe(200);
    const payload = (await recovery.json()) as {
      client: { passkeyCount: number };
      enrollmentUrl: string;
      expiresAt: number;
    };
    expect(payload.client.passkeyCount).toBe(0);
    expect(payload.enrollmentUrl).toMatch(/^http:\/\/localhost:4173\/enroll#token=[a-z2-7]{52}$/u);
    expect(payload.expiresAt).toBeGreaterThan(Date.now());

    // Old session is dead after bulk revoke.
    const oldSession = await app.request('/api/session', {
      headers: { Cookie: subject.cookie, Origin: publicOrigin },
    });
    expect(oldSession.status).toBe(401);

    const self = await app.request(`/api/clients/${administrator.id}/re-enroll`, {
      method: 'POST',
      headers,
    });
    expect(self.status).toBe(409);
  });
});
