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
    cookie: `localwebauthn_demo_session=${sessionToken}`,
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
    expect(exchanged.headers.get('set-cookie')).toContain('localwebauthn_demo_enrollment=');

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
    expect(options.headers.get('set-cookie')).toContain('localwebauthn_demo_challenge=');
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
      headers: { Cookie: `localwebauthn_demo_session=${otherToken}`, Origin: publicOrigin },
    });
    expect(other.status).toBe(401);
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
