import { afterEach, describe, expect, it, vi } from 'vitest';

import type { SignupEvent, SignupEventSink } from '@localwebauthn/channels-core';

import type { DemoDatabase, DemoRole } from '../src/database';

import { createOpaqueToken, createUserHandle, sha256 } from '@localwebauthn/server';
import { randomUUID } from 'node:crypto';

import { createDemoApplication, ensureBootstrapAdministrator } from '../src/application';
import { cancelRecoveriesAfterCredentialAuthentication } from '../src/auth';
import { openDemoDatabase, reapSignups } from '../src/database';

const publicOrigin = 'http://localhost:4173';
const databases: DemoDatabase[] = [];

function setup(
  options: {
    recoveryDelayMs?: number;
    recoveryClaimWindowMs?: number;
    onSignupEvent?: SignupEventSink;
  } = {},
) {
  const database = openDemoDatabase(':memory:');
  databases.push(database);
  const application = createDemoApplication(database, {
    auth: {
      publicOrigin,
      rpId: 'localhost',
      rpName: 'LocalWebAuthn Test',
    },
    ...options,
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

/** Start a signup and harvest the per-channel OTPs from the simulated inbox. */
async function startSignup(
  app: { request: (path: string, init?: RequestInit) => Response | Promise<Response> },
  input: { displayName: string; email: string; phone: string },
): Promise<{ signupId: string; recovery: boolean; otps: Record<string, string> }> {
  const started = await app.request('/api/signup/start', {
    method: 'POST',
    headers: { Origin: publicOrigin, 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  const payload = (await started.json()) as {
    signupId: string;
    recovery: boolean;
    simulated: { body: string }[];
  };
  const otps: Record<string, string> = {};
  for (const message of payload.simulated) {
    const url = new URL(/https?:\/\/\S+/u.exec(message.body)?.[0] ?? '');
    const fragment = new URLSearchParams(url.hash.slice(1));
    otps[fragment.get('channel') ?? ''] = fragment.get('otp') ?? '';
  }
  return { signupId: payload.signupId, recovery: payload.recovery, otps };
}

afterEach(() => {
  vi.restoreAllMocks();
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

  /**
   * A plain signup whose escrowed token has gone missing must refuse, not improvise.
   *
   * `claimEnrollment` serves both signup and recovery, because `verifySignupProof`
   * reports `'completed'` for both. It used to tell them apart only by whether a
   * token happened to be stored, so an empty column sent a *plain signup* claim into
   * the recovery branch — which revokes every credential the account has. A person
   * re-opening their own link after enrolling would have had their passkey revoked
   * and been handed a new invitation, silently.
   *
   * The kind is now checked explicitly. This test is the guard: it empties the column
   * and requires a refusal *and* an intact credential.
   */
  it('refuses a plain-signup claim with no stored token instead of revoking', async () => {
    const { app, database } = setup();
    const headers = { Origin: publicOrigin, 'Content-Type': 'application/json' };

    const { signupId, otps } = await startSignup(app, {
      displayName: 'Grace Signup',
      email: 'grace@example.test',
      phone: '+15551230009',
    });
    const prove = (channel: string, otp: string) =>
      app.request('/api/signup/prove', {
        method: 'POST',
        headers,
        body: JSON.stringify({ signupId, channel, otp }),
      });

    await prove('email', otps.email);
    const completed = await prove('phone', otps.phone);
    const { enrollmentToken } = (await completed.json()) as { enrollmentToken: string };

    // Enrol for real, so there is a credential the recovery branch could destroy.
    const exchanged = await app.request('/api/auth/enrollment/exchange', {
      method: 'POST',
      headers,
      body: JSON.stringify({ token: enrollmentToken }),
    });
    expect(exchanged.status).toBe(200);
    const clientId = (
      database.prepare(`SELECT client_id FROM demo_signups WHERE id = ?`).get(signupId) as
        { client_id: string } | undefined
    )?.client_id;
    expect(clientId).toBeTruthy();
    database
      .prepare(
        `INSERT INTO localwebauthn_credentials(
           id, user_id, public_key, counter, transports_json, device_type,
           backed_up, label, created_at
         ) VALUES (?, ?, X'00', 0, '[]', 'multiDevice', 1, 'Enrolled passkey', ?)`,
      )
      .run(`credential-${signupId}`, clientId, Date.now());

    // Now lose the escrow, which is exactly what the withdrawn "clear it once
    // spent" change would have done.
    database.prepare(`UPDATE demo_signups SET enrollment_token = NULL WHERE id = ?`).run(signupId);

    const grantCount = (): number =>
      (
        database
          .prepare(`SELECT COUNT(*) AS n FROM localwebauthn_enrollment_grants WHERE user_id = ?`)
          .get(clientId) as { n: number }
      ).n;
    const before = grantCount();

    const reopened = await prove('email', otps.email);
    expect(reopened.status).toBe(409);
    await expect(reopened.json()).resolves.toMatchObject({ error: 'signup_incomplete' });

    // The credential survived — this is the assertion the old code would fail, since
    // it would have revoked every credential this account has.
    const live = database
      .prepare(
        `SELECT COUNT(*) AS n FROM localwebauthn_credentials
         WHERE user_id = ? AND revoked_at IS NULL`,
      )
      .get(clientId) as { n: number };
    expect(live.n).toBe(1);
    // And the refusal minted nothing: no fresh invitation was handed to whoever
    // presented that OTP.
    expect(grantCount()).toBe(before);
  });

  /**
   * The proofing machine is host-owned, so `@localwebauthn/server`'s `onEvent` never
   * sees it — the core's first sight of a self-serve flow is `enrollment.issued`, at
   * completion. Without these events, starting a signup, proving a channel,
   * presenting a wrong OTP and vetoing are all invisible; and since expired rows are
   * reaped, afterwards there is no record they happened at all.
   */
  it('reports the signup lifecycle, including the rejected proofs', async () => {
    const events: SignupEvent[] = [];
    const { app } = setup({
      onSignupEvent: (event) => {
        events.push(event);
      },
    });
    const headers = { Origin: publicOrigin, 'Content-Type': 'application/json' };
    const { signupId, otps } = await startSignup(app, {
      displayName: 'Ida Logged',
      email: 'ida@example.test',
      phone: '+15551230011',
    });
    const prove = (channel: string, otp: string) =>
      app.request('/api/signup/prove', {
        method: 'POST',
        headers,
        body: JSON.stringify({ signupId, channel, otp }),
      });

    await prove('email', 'wrong-otp');
    await prove('email', otps.email);
    await prove('phone', otps.phone);
    // Claim-on-reopen: the second claim is the one that was previously unobservable.
    await prove('email', otps.email);

    expect(events.map((event) => event.type)).toEqual([
      'signup.started',
      'signup.proof', // invalid
      'signup.proof', // proved
      'signup.proof', // proved
      'signup.completed',
      'signup.claimed',
      'signup.proof', // completed
      'signup.claimed',
    ]);
    expect(events[0]).toMatchObject({
      type: 'signup.started',
      kind: 'signup',
      channels: ['email', 'phone'],
    });
    // A guessed OTP is reported, which is the point: a run of these against one
    // signup is somebody guessing, and nothing else would show it.
    expect(events[1]).toMatchObject({ type: 'signup.proof', outcome: 'invalid' });
    // The claim counter distinguishes the person finishing from a later claim.
    const claims = events.filter((event) => event.type === 'signup.claimed');
    expect(claims.map((event) => event.claimCount)).toEqual([1, 2]);

    // Nothing in this stream may carry a secret or a destination: it goes to logs.
    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain(otps.email);
    expect(serialized).not.toContain(otps.phone);
    expect(serialized).not.toContain('ida@example.test');
    expect(serialized).not.toContain('+15551230011');
    expect(serialized).not.toMatch(/[a-z2-7]{52}/u);
  });

  it('contains synchronous and asynchronous signup telemetry failures after state commits', async () => {
    const warning = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const attempts: string[] = [];
    const { app, database } = setup({
      onSignupEvent: async (event) => {
        await Promise.resolve();
        attempts.push(event.type);
        throw new Error('telemetry unavailable');
      },
    });
    const headers = { Origin: publicOrigin, 'Content-Type': 'application/json' };
    const started = await startSignup(app, {
      displayName: 'State Wins',
      email: 'state-wins@example.test',
      phone: '+15551230012',
    });
    const prove = (channel: string) =>
      app.request('/api/signup/prove', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          signupId: started.signupId,
          channel,
          otp: started.otps[channel],
        }),
      });

    expect((await prove('email')).status).toBe(200);
    const completed = await prove('phone');
    expect(completed.status).toBe(200);
    await expect(completed.json()).resolves.toMatchObject({ complete: true });
    const row = database
      .prepare(`SELECT consumed_at, enrollment_token FROM demo_signups WHERE id = ?`)
      .get(started.signupId) as { consumed_at: number | null; enrollment_token: string | null };
    expect(row.consumed_at).not.toBeNull();
    expect(row.enrollment_token).not.toBeNull();
    expect(attempts).toContain('signup.completed');
    expect(attempts).toContain('signup.claimed');
    expect(warning).toHaveBeenCalled();
  });

  /**
   * The veto after completion — the case it exists for, and the case that used to do
   * nothing. `cancelSignup` was gated on `enrollment_token IS NULL`, so the veto became
   * a no-op the moment there was something worth vetoing. `canCancelSignup` in
   * channels-core always admitted `'completed'`; only the storage refused.
   *
   * A previous version of this test asserted that no-op as if it were the
   * specification. It was the bug, written down.
   */
  it('vetoes after completion, revoking everything the signup produced', async () => {
    const events: SignupEvent[] = [];
    const { app, database, authentication } = setup({
      onSignupEvent: (event) => {
        events.push(event);
      },
    });
    const headers = { Origin: publicOrigin, 'Content-Type': 'application/json' };
    const started = await startSignup(app, {
      displayName: 'Already Complete',
      email: 'already-complete@example.test',
      phone: '+15551230013',
    });
    const post = (path: string, channel: string) =>
      app.request(path, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          signupId: started.signupId,
          channel,
          otp: started.otps[channel],
        }),
      });
    await post('/api/signup/prove', 'email');
    const completed = await post('/api/signup/prove', 'phone');
    const { enrollmentToken } = (await completed.json()) as { enrollmentToken: string };

    // Enrol for real, so the veto has a live grant, session and credential to undo.
    expect(
      (
        await app.request('/api/auth/enrollment/exchange', {
          method: 'POST',
          headers,
          body: JSON.stringify({ token: enrollmentToken }),
        })
      ).status,
    ).toBe(200);
    const clientId = (
      database.prepare(`SELECT client_id FROM demo_signups WHERE id = ?`).get(started.signupId) as {
        client_id: string;
      }
    ).client_id;
    database
      .prepare(
        `INSERT INTO localwebauthn_credentials(
           id, user_id, public_key, counter, transports_json, device_type,
           backed_up, label, created_at
         ) VALUES (?, ?, X'00', 0, '[]', 'multiDevice', 1, 'Enrolled passkey', ?)`,
      )
      .run(`credential-${started.signupId}`, clientId, Date.now());
    const generation = (): number =>
      (
        database
          .prepare(`SELECT generation FROM localwebauthn_registration_fences WHERE user_id = ?`)
          .get(clientId) as { generation: number } | undefined
      )?.generation ?? 0;
    const before = generation();

    // The *other* channel vetoes — the compromise case this control is for.
    const canceled = await post('/api/signup/cancel', 'email');
    expect(canceled.status).toBe(200);
    await expect(canceled.json()).resolves.toEqual({ canceled: true, revokedAccess: true });

    const row = database
      .prepare(`SELECT canceled_at FROM demo_signups WHERE id = ?`)
      .get(started.signupId) as { canceled_at: number | null };
    expect(row.canceled_at).not.toBeNull();

    // Nothing the signup produced can authenticate any more.
    const credentials = await authentication.listCredentials(clientId, true);
    expect(credentials).not.toHaveLength(0);
    expect(credentials.every((credential) => credential.revokedAt !== null)).toBe(true);
    // The registration fence moved, so a ceremony already in flight cannot land after
    // the veto.
    expect(generation()).toBeGreaterThan(before);
    // No pending grant survives. This is the assertion that separates the unscoped
    // revoke from a credential-tree walk: a walk bumps the fence as well, but leaves the
    // grant, so the link could be exchanged again and an enrollment session already
    // opened from it would stay valid.
    expect(
      database
        .prepare(
          `SELECT COUNT(*) AS n FROM localwebauthn_enrollment_grants
           WHERE user_id = ? AND completed_at IS NULL AND revoked_at IS NULL`,
        )
        .get(clientId),
    ).toEqual({ n: 0 });

    expect(events).toContainEqual(
      expect.objectContaining({
        type: 'signup.canceled',
        cause: 'channel_proof',
        revokedAccess: true,
      }),
    );

    // Terminal and idempotent: a second veto succeeds and reports honestly that there
    // was nothing left to revoke.
    await expect((await post('/api/signup/cancel', 'phone')).json()).resolves.toEqual({
      canceled: true,
      revokedAccess: false,
    });
  });

  it('vetoes before completion without revoking anything', async () => {
    const events: SignupEvent[] = [];
    const { app } = setup({
      onSignupEvent: (event) => {
        events.push(event);
      },
    });
    const headers = { Origin: publicOrigin, 'Content-Type': 'application/json' };
    const started = await startSignup(app, {
      displayName: 'Early Veto',
      email: 'early@example.test',
      phone: '+15551230023',
    });
    const post = (path: string, channel: string) =>
      app.request(path, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          signupId: started.signupId,
          channel,
          otp: started.otps[channel],
        }),
      });

    // One channel proved, the other vetoes. No account exists yet, so marking the row
    // is the whole of the veto and `revokedAccess` must say so.
    await post('/api/signup/prove', 'email');
    await expect((await post('/api/signup/cancel', 'phone')).json()).resolves.toEqual({
      canceled: true,
      revokedAccess: false,
    });
    expect(events).toContainEqual(
      expect.objectContaining({ type: 'signup.canceled', revokedAccess: false }),
    );

    // And the signup is dead: the remaining channel cannot complete it.
    await expect((await post('/api/signup/prove', 'phone')).json()).resolves.toMatchObject({
      canceled: true,
    });
  });

  it('reports each signup it actually reaps', async () => {
    const { database } = setup();
    const events: SignupEvent[] = [];
    database
      .prepare(
        `INSERT INTO demo_signups(
           id, email, phone, display_name, otp_email_hash, otp_phone_hash,
           email_proved_at, expires_at, created_at
         ) VALUES ('abandoned', 'gone@example.test', '+15551230000', 'Gone',
                   X'00', X'01', 500, 1000, 400)`,
      )
      .run();

    await expect(reapSignups(database, 2_000, (event) => events.push(event))).resolves.toBe(1);
    expect(events).toEqual([
      {
        type: 'signup.reaped',
        at: 2_000,
        signupId: 'abandoned',
        kind: 'signup',
        proved: ['email'],
        completed: false,
      },
    ]);
    // The row is gone, so this line is the only remaining record of it.
    expect(database.prepare(`SELECT COUNT(*) AS n FROM demo_signups`).get()).toEqual({ n: 0 });
  });

  it('reaps signup rows once their window closes, and spares live ones', async () => {
    const { database } = setup();
    const insert = (id: string, expiresAt: number): void => {
      database
        .prepare(
          `INSERT INTO demo_signups(
             id, email, phone, display_name, otp_email_hash, otp_phone_hash,
             expires_at, created_at
           ) VALUES (?, ?, '+15551230000', 'Someone', X'00', X'01', ?, ?)`,
        )
        .run(id, `${id}@example.test`, expiresAt, Date.now());
    };
    insert('past', 1_000);
    insert('future', Date.now() + 60_000);

    await expect(reapSignups(database, Date.now())).resolves.toBe(1);
    const remaining = database.prepare(`SELECT id FROM demo_signups`).all() as { id: string }[];
    expect(remaining.map((row) => row.id)).toEqual(['future']);
  });

  it('finishes reaping when its telemetry sink fails', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const { database } = setup();
    database
      .prepare(
        `INSERT INTO demo_signups(
           id, email, phone, display_name, otp_email_hash, otp_phone_hash,
           expires_at, created_at
         ) VALUES ('doomed', 'doomed@example.test', '+15551230000', 'Doomed',
                   X'00', X'01', 1000, 400)`,
      )
      .run();

    await expect(
      reapSignups(database, 2_000, async () => {
        await Promise.resolve();
        throw new Error('telemetry unavailable');
      }),
    ).resolves.toBe(1);
    expect(database.prepare(`SELECT COUNT(*) AS n FROM demo_signups`).get()).toEqual({ n: 0 });
  });

  it('recovery waits out the delay, touches nothing meanwhile, and refuses administrators', async () => {
    const { app, database } = setup({ recoveryDelayMs: 100, recoveryClaimWindowMs: 60_000 });
    const subject = await authenticatedClient(database, 'client');
    const administrator = await authenticatedClient(database, 'administrator');
    const headers = { Origin: publicOrigin, 'Content-Type': 'application/json' };
    const sessionCheck = () =>
      app.request('/api/session', { headers: { Cookie: subject.cookie, Origin: publicOrigin } });

    const { signupId, otps, recovery } = await startSignup(app, {
      displayName: 'Ignored For Recovery',
      email: `client-${subject.id}@example.test`,
      phone: '+15551230001',
    });
    expect(recovery).toBe(true);
    const prove = (channel: string) =>
      app.request('/api/signup/prove', {
        method: 'POST',
        headers,
        body: JSON.stringify({ signupId, channel, otp: otps[channel] }),
      });

    await expect((await prove('email')).json()).resolves.toMatchObject({ complete: false });
    const completed = (await (await prove('phone')).json()) as {
      complete: boolean;
      pending?: boolean;
      claimableAt?: number;
    };
    // Recovery is not signup: completion opens a waiting period instead of
    // releasing a token, and the account is untouched during it.
    expect(completed).toMatchObject({ complete: false, pending: true });
    expect(completed.claimableAt).toBeGreaterThan(Date.now());
    expect((await sessionCheck()).status).toBe(200);
    await expect((await prove('email')).json()).resolves.toMatchObject({ pending: true });

    // After the window, any channel's OTP claims; only now is the account
    // revoked and the fresh enrollment issued.
    await new Promise((resolve) => setTimeout(resolve, 120));
    const claimed = (await (await prove('email')).json()) as {
      complete: boolean;
      enrollmentToken: string;
    };
    expect(claimed.complete).toBe(true);
    expect((await sessionCheck()).status).toBe(401);
    const exchanged = await app.request('/api/auth/enrollment/exchange', {
      method: 'POST',
      headers,
      body: JSON.stringify({ token: claimed.enrollmentToken }),
    });
    expect(exchanged.status).toBe(200);

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

  it('any valid channel OTP vetoes a recovery, and a passkey sign-in vetoes it too', async () => {
    const events: SignupEvent[] = [];
    const { app, database, signupEvents } = setup({
      recoveryDelayMs: 60_000,
      onSignupEvent: (event) => {
        events.push(event);
      },
    });
    const subject = await authenticatedClient(database, 'client');
    const headers = { Origin: publicOrigin, 'Content-Type': 'application/json' };
    const email = `client-${subject.id}@example.test`;

    // Veto during the pending window, from a channel that never confirmed
    // anything: cancel authority does not require a prior proof.
    const first = await startSignup(app, { displayName: 'X', email, phone: '+15551230003' });
    const prove = (id: string, otps: Record<string, string>, channel: string) =>
      app.request('/api/signup/prove', {
        method: 'POST',
        headers,
        body: JSON.stringify({ signupId: id, channel, otp: otps[channel] }),
      });
    await prove(first.signupId, first.otps, 'email');
    await expect((await prove(first.signupId, first.otps, 'phone')).json()).resolves.toMatchObject({
      pending: true,
    });
    const cancel = await app.request('/api/signup/cancel', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        signupId: first.signupId,
        channel: 'email',
        otp: first.otps.email,
      }),
    });
    // Nothing to revoke: recovery's completion only opens the delay window, so no
    // grant, credential or session exists until the first mature claim. That is the
    // whole point of the waiting period, and `revokedAccess` records it.
    await expect(cancel.json()).resolves.toEqual({ canceled: true, revokedAccess: false });
    await expect(
      app.request('/api/signup/cancel', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          signupId: first.signupId,
          channel: 'email',
          otp: first.otps.email,
        }),
      }),
    ).resolves.toHaveProperty('status', 200);
    await expect((await prove(first.signupId, first.otps, 'phone')).json()).resolves.toMatchObject({
      canceled: true,
      complete: false,
    });
    expect(events.filter((event) => event.type === 'signup.canceled')).toEqual([
      expect.objectContaining({
        signupId: first.signupId,
        cause: 'channel_proof',
      }),
    ]);
    // The account never changed.
    expect(
      (
        await app.request('/api/session', {
          headers: { Cookie: subject.cookie, Origin: publicOrigin },
        })
      ).status,
    ).toBe(200);

    // Signal-style activity veto: a passkey sign-in cancels a live recovery.
    // (The hook fires on the credential.authenticated event; the e2e drives a
    // real sign-in — here we exercise the same helper the hook calls.)
    const second = await startSignup(app, { displayName: 'X', email, phone: '+15551230003' });
    const third = await startSignup(app, { displayName: 'X', email, phone: '+15551230004' });
    const expired = await startSignup(app, { displayName: 'X', email, phone: '+15551230005' });
    database
      .prepare(`UPDATE demo_signups SET expires_at = ? WHERE id = ?`)
      .run(Date.now() - 1, expired.signupId);
    await prove(second.signupId, second.otps, 'email');
    const activityCanceled = await cancelRecoveriesAfterCredentialAuthentication(
      database,
      subject.id,
      Date.now(),
      signupEvents,
    );
    expect(new Set(activityCanceled)).toEqual(new Set([second.signupId, third.signupId]));
    await expect(
      (await prove(second.signupId, second.otps, 'phone')).json(),
    ).resolves.toMatchObject({ canceled: true, complete: false });
    const cancellationEvents = events.filter((event) => event.type === 'signup.canceled');
    expect(cancellationEvents).toHaveLength(3);
    expect(cancellationEvents).toContainEqual(
      expect.objectContaining({ signupId: first.signupId, cause: 'channel_proof' }),
    );
    for (const signupId of [second.signupId, third.signupId]) {
      expect(cancellationEvents).toContainEqual(
        expect.objectContaining({ signupId, cause: 'credential_authenticated' }),
      );
    }
    expect(
      database.prepare(`SELECT canceled_at FROM demo_signups WHERE id = ?`).get(expired.signupId),
    ).toEqual({ canceled_at: null });
    await expect(
      cancelRecoveriesAfterCredentialAuthentication(database, subject.id, Date.now(), signupEvents),
    ).resolves.toEqual([]);
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
