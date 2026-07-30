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
});
