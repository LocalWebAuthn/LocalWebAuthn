import type { EnrollmentIssue } from '@localwebauthn/server';
import {
  createUserHandle,
  describeSignupPhase,
  isLocalWebAuthnError,
  signupPhase,
} from '@localwebauthn/server';
import { serveStatic } from '@hono/node-server/serve-static';
import { Hono } from 'hono';
import type { MiddlewareHandler } from 'hono';
import { randomUUID } from 'node:crypto';

import type { DemoAuthConfig, DemoAuthentication, DemoEnvironment } from './auth';
import type { DemoClient, DemoDatabase, DemoSignup } from './database';

import {
  assertE164,
  createSignupChallenge,
  signupMissing,
  signupProofEmail,
  signupProofSms,
  signupProofUrl,
  signupSatisfied,
  verifySignupProof,
  type SignupProofState,
} from '@localwebauthn/channels-core';

import {
  createDemoAuthentication,
  currentSessionToken,
  mountAuthenticationRoutes,
  requireAuthentication,
  requireExpectedOrigin,
} from './auth';
import {
  clientByEmail,
  clientById,
  completeSignup,
  insertSignup,
  listClients,
  markSignupProved,
  signupById,
} from './database';

export type DemoApplicationOptions = {
  auth: DemoAuthConfig;
  staticRoot?: string;
};

type ClientPayload = DemoClient & {
  passkeyCount: number;
  /** Host-facing signup phase from `@localwebauthn/server` signupPhase(). */
  signupPhase: ReturnType<typeof signupPhase>;
  signupPhaseLabel: string;
};

function validEmail(email: string): boolean {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/u.test(email);
}

async function clientPayload(
  client: DemoClient,
  authentication: DemoAuthentication,
): Promise<ClientPayload> {
  const passkeyCount = (await authentication.listCredentials(client.id)).length;
  const phase = signupPhase({
    hasActiveCredential: passkeyCount > 0,
    // Demo treats "no passkeys yet" as an outstanding invite for admin tables.
    hasPendingEnrollmentGrant: passkeyCount === 0,
    hasEnrollmentSession: false,
  });
  return {
    ...client,
    passkeyCount,
    signupPhase: phase,
    signupPhaseLabel: describeSignupPhase(phase),
  };
}

export async function ensureBootstrapAdministrator(
  database: DemoDatabase,
  authentication: DemoAuthentication,
  input: {
    email: string;
    displayName: string;
  },
): Promise<EnrollmentIssue | null> {
  const email = input.email.trim().toLowerCase();
  const displayName = input.displayName.trim();
  if (!validEmail(email) || !displayName) {
    throw new Error('The bootstrap administrator requires a valid email and display name.');
  }

  let administrator = clientByEmail(database, email);
  if (!administrator) {
    const id = randomUUID();
    const now = Date.now();
    database
      .prepare(
        `INSERT INTO demo_clients(
           id, email, display_name, role, webauthn_user_handle, created_at
         ) VALUES (?, ?, ?, 'administrator', ?, ?)`,
      )
      .run(id, email, displayName, createUserHandle(), now);
    administrator = clientById(database, id);
  }
  if (!administrator || administrator.role !== 'administrator') {
    throw new Error('The bootstrap email belongs to a non-administrator client.');
  }
  if ((await authentication.listCredentials(administrator.id)).length > 0) {
    return null;
  }
  return authentication.issueEnrollment(administrator.id);
}

const SIGNUP_CHANNELS = ['email', 'phone'] as const;
type DemoSignupChannel = (typeof SIGNUP_CHANNELS)[number];

function signupProofState(signup: DemoSignup): SignupProofState & {
  otpHashes: Record<DemoSignupChannel, Uint8Array>;
} {
  return {
    expiresAt: signup.expiresAt,
    consumedAt: signup.consumedAt,
    provedAt: { email: signup.emailProvedAt, phone: signup.phoneProvedAt },
    otpHashes: { email: signup.otpEmailHash, phone: signup.otpPhoneHash },
  };
}

/**
 * Self-serve signup with SIMULATED delivery: instead of sending email and SMS,
 * `start` returns the two proof messages so the UI can display them as a
 * pretend inbox. Everything else — the state machine, claim-on-reopen, the
 * enrollment issued only after both proofs — is the real flow; swap the
 * simulated response for `channels-node` / `channels-cf` senders in a real app.
 *
 * Host duties this demo skips on purpose: rate limiting and bot defense on
 * `start` (it sends two messages per call in a real deployment), and
 * disposable-domain policy. See docs/COMPARISON.md.
 */
function mountSignupRoutes(
  app: Hono<DemoEnvironment>,
  database: DemoDatabase,
  authentication: DemoAuthentication,
  config: DemoAuthConfig,
): void {
  app.post('/api/signup/start', async (context) => {
    const body = await context.req
      .json<{ email?: unknown; phone?: unknown; displayName?: unknown }>()
      .catch((): { email?: unknown; phone?: unknown; displayName?: unknown } => ({}));
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const displayName = typeof body.displayName === 'string' ? body.displayName.trim() : '';
    let phone: string;
    try {
      phone = assertE164(typeof body.phone === 'string' ? body.phone : '');
    } catch {
      phone = '';
    }
    if (!validEmail(email) || !phone || !displayName || displayName.length > 120) {
      return context.json(
        {
          error: 'invalid_signup',
          message: 'A display name, valid email, and E.164 phone number are required.',
        },
        400,
      );
    }

    // Existing accounts make this a RE-enrollment (recovery by proofing).
    // Administrators are excluded: they recover through another administrator,
    // so channel compromise alone can never take over an admin account.
    const existing = clientByEmail(database, email);
    if (existing?.role === 'administrator') {
      return context.json(
        {
          error: 'not_self_serve',
          message: 'This account cannot use self-serve signup.',
        },
        409,
      );
    }

    const challenge = await createSignupChallenge(SIGNUP_CHANNELS);
    insertSignup(database, {
      id: challenge.signupId,
      email,
      phone,
      displayName: existing?.displayName ?? displayName,
      otpEmailHash: challenge.otpHashes.email,
      otpPhoneHash: challenge.otpHashes.phone,
      expiresAt: challenge.expiresAt,
    });

    const appName = config.rpName;
    const emailUrl = signupProofUrl(
      config.publicOrigin,
      challenge.signupId,
      'email',
      challenge.otps.email,
    );
    const phoneUrl = signupProofUrl(
      config.publicOrigin,
      challenge.signupId,
      'phone',
      challenge.otps.phone,
    );
    return context.json(
      {
        signupId: challenge.signupId,
        expiresAt: challenge.expiresAt,
        recovery: existing !== null,
        // Simulated delivery: a real host sends these and returns nothing.
        simulated: [
          {
            channel: 'email',
            to: email,
            subject: signupProofEmail({ appName, url: emailUrl }).subject,
            body: signupProofEmail({ appName, url: emailUrl }).text,
          },
          {
            channel: 'phone',
            to: phone,
            body: signupProofSms({ appName, url: phoneUrl }),
          },
        ],
      },
      201,
    );
  });

  app.post('/api/signup/prove', async (context) => {
    const body = await context.req
      .json<{ signupId?: unknown; channel?: unknown; otp?: unknown }>()
      .catch((): { signupId?: unknown; channel?: unknown; otp?: unknown } => ({}));
    const signupId = typeof body.signupId === 'string' ? body.signupId : '';
    const otp = typeof body.otp === 'string' ? body.otp : '';
    const channel = SIGNUP_CHANNELS.find((candidate) => candidate === body.channel);
    const signup = signupId ? signupById(database, signupId) : null;
    if (!signup || !channel || !otp) {
      return context.json(
        { error: 'invalid_proof', message: 'This confirmation link is not valid.' },
        403,
      );
    }

    const now = Date.now();
    const state = signupProofState(signup);
    const outcome = await verifySignupProof(state, { channel, otp }, now);

    if (outcome === 'invalid') {
      return context.json(
        { error: 'invalid_proof', message: 'This confirmation link is not valid.' },
        403,
      );
    }
    if (outcome === 'expired') {
      return context.json(
        { error: 'signup_expired', message: 'This signup expired. Start over.' },
        410,
      );
    }
    if (outcome === 'completed') {
      // Claim-on-reopen: any proved channel's link now opens enrollment.
      return context.json({
        complete: true,
        enrollmentToken: signup.enrollmentToken,
        user: { name: signup.email, displayName: signup.displayName },
      });
    }

    if (outcome === 'proved') {
      markSignupProved(database, signup.id, channel, now);
      state.provedAt[channel] = now;
    }

    if (!signupSatisfied(SIGNUP_CHANNELS, state)) {
      return context.json({
        complete: false,
        proved: SIGNUP_CHANNELS.filter((required) => Boolean(state.provedAt[required])),
        missing: signupMissing(SIGNUP_CHANNELS, state),
      });
    }

    // Final proof landed: only now does the enrollment grant come to exist.
    const existing = clientByEmail(database, signup.email);
    if (existing?.role === 'administrator') {
      return context.json(
        { error: 'not_self_serve', message: 'This account cannot use self-serve signup.' },
        409,
      );
    }
    let clientId: string;
    if (existing) {
      // Recovery: both channels re-proved; revoke before issuing (documented order).
      await authentication.revokeUserAuthentication(existing.id);
      clientId = existing.id;
    } else {
      clientId = randomUUID();
      database
        .prepare(
          `INSERT INTO demo_clients(
             id, email, display_name, role, webauthn_user_handle, created_at
           ) VALUES (?, ?, ?, 'client', ?, ?)`,
        )
        .run(clientId, signup.email, signup.displayName, createUserHandle(), now);
    }
    const enrollment = await authentication.issueEnrollment(clientId);
    completeSignup(database, signup.id, {
      clientId,
      enrollmentToken: enrollment.enrollmentToken,
      now,
    });
    return context.json({
      complete: true,
      enrollmentToken: enrollment.enrollmentToken,
      user: { name: signup.email, displayName: signup.displayName },
    });
  });
}

export function createDemoApplication(database: DemoDatabase, options: DemoApplicationOptions) {
  const app = new Hono<DemoEnvironment>();
  const authentication = createDemoAuthentication(database, options.auth);

  app.use('/api/*', requireExpectedOrigin(options.auth));
  mountAuthenticationRoutes(app, authentication, options.auth);
  mountSignupRoutes(app, database, authentication, options.auth);

  const authenticated = requireAuthentication(authentication, options.auth);
  const administrator: MiddlewareHandler<DemoEnvironment> = async (context, next) => {
    const current = clientById(database, context.get('authenticatedUser').id);
    if (current?.role !== 'administrator') {
      return context.json(
        {
          error: 'forbidden',
          message: 'Administrator access is required.',
        },
        403,
      );
    }
    await next();
  };

  app.get('/api/session', authenticated, async (context) => {
    const current = clientById(database, context.get('authenticatedUser').id);
    if (!current) {
      return context.json({ error: 'unauthenticated', message: 'The client is unavailable.' }, 401);
    }
    return context.json({
      client: await clientPayload(current, authentication),
      passkeys: (await authentication.listCredentials(current.id)).map((credential) => ({
        id: credential.id,
        label: credential.label,
        deviceType: credential.deviceType,
        backedUp: credential.backedUp,
        createdAt: credential.createdAt,
        lastUsedAt: credential.lastUsedAt,
      })),
    });
  });

  app.get('/api/clients', authenticated, administrator, async (context) =>
    context.json({
      clients: await Promise.all(
        listClients(database).map((client) => clientPayload(client, authentication)),
      ),
    }),
  );

  app.post('/api/clients', authenticated, administrator, async (context) => {
    const body = await context.req
      .json<{ email?: unknown; displayName?: unknown }>()
      .catch((): { email?: unknown; displayName?: unknown } => ({}));
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
    const displayName = typeof body.displayName === 'string' ? body.displayName.trim() : '';
    if (!validEmail(email) || !displayName || displayName.length > 120) {
      return context.json(
        {
          error: 'invalid_client',
          message: 'Enter a valid display name and email address.',
        },
        400,
      );
    }

    if (clientByEmail(database, email)) {
      return context.json(
        {
          error: 'email_exists',
          message: 'A client with that email already exists.',
        },
        409,
      );
    }

    const id = randomUUID();
    try {
      database
        .prepare(
          `INSERT INTO demo_clients(
             id, email, display_name, role, webauthn_user_handle, created_at
           ) VALUES (?, ?, ?, 'client', ?, ?)`,
        )
        .run(id, email, displayName, createUserHandle(), Date.now());
      const enrollment = await authentication.issueEnrollment(
        id,
        context.get('authenticatedUser').id,
      );
      const created = clientById(database, id);
      if (!created) {
        throw new Error('The client was not persisted.');
      }
      return context.json(
        {
          client: await clientPayload(created, authentication),
          enrollmentUrl: enrollment.enrollmentUrl,
          expiresAt: enrollment.expiresAt,
        },
        201,
      );
    } catch {
      return context.json(
        {
          error: 'client_creation_failed',
          message: 'The client could not be created.',
        },
        500,
      );
    }
  });

  app.post('/api/clients/:clientId/enrollment', authenticated, administrator, async (context) => {
    const client = clientById(database, context.req.param('clientId'));
    if (!client?.active) {
      return context.json({ error: 'client_not_found', message: 'The client was not found.' }, 404);
    }
    const enrollment = await authentication.issueEnrollment(
      client.id,
      context.get('authenticatedUser').id,
    );
    return context.json({
      enrollmentUrl: enrollment.enrollmentUrl,
      expiresAt: enrollment.expiresAt,
    });
  });

  /**
   * Recovery as documented in the package README: revoke every passkey and
   * session for the client, then issue a fresh enrollment link. Order matters —
   * issuing first would destroy the link you just created.
   */
  app.post('/api/clients/:clientId/re-enroll', authenticated, administrator, async (context) => {
    const currentUserId = context.get('authenticatedUser').id;
    const client = clientById(database, context.req.param('clientId'));
    if (!client?.active) {
      return context.json({ error: 'client_not_found', message: 'The client was not found.' }, 404);
    }
    if (client.id === currentUserId) {
      return context.json(
        {
          error: 'self_recovery',
          message: 'Add another passkey while signed in, or recover from a second administrator.',
        },
        409,
      );
    }
    await authentication.revokeUserAuthentication(client.id);
    const enrollment = await authentication.issueEnrollment(
      client.id,
      context.get('authenticatedUser').id,
    );
    return context.json({
      client: await clientPayload(client, authentication),
      enrollmentUrl: enrollment.enrollmentUrl,
      expiresAt: enrollment.expiresAt,
    });
  });

  app.post(
    '/api/clients/:clientId/revoke-authentication',
    authenticated,
    administrator,
    async (context) => {
      const currentUserId = context.get('authenticatedUser').id;
      const client = clientById(database, context.req.param('clientId'));
      if (!client) {
        return context.json(
          { error: 'client_not_found', message: 'The client was not found.' },
          404,
        );
      }
      if (client.id === currentUserId) {
        return context.json(
          {
            error: 'self_revocation',
            message: 'Use the passkey list to manage your own credentials.',
          },
          409,
        );
      }
      await authentication.revokeUserAuthentication(client.id);
      return context.json({
        client: await clientPayload(client, authentication),
      });
    },
  );

  /**
   * Sessions-only response for when a session, not a passkey, is the problem
   * (stolen laptop, suspected cookie theft). Contrast with Re-enroll: the
   * person's passkeys stay valid and they simply sign in again.
   */
  app.post(
    '/api/clients/:clientId/revoke-sessions',
    authenticated,
    administrator,
    async (context) => {
      const client = clientById(database, context.req.param('clientId'));
      if (!client) {
        return context.json(
          { error: 'client_not_found', message: 'The client was not found.' },
          404,
        );
      }
      const revokedSessions = await authentication.revokeUserSessions(client.id);
      return context.json({
        client: await clientPayload(client, authentication),
        revokedSessions,
      });
    },
  );

  /** Self-service "sign out my other devices": the calling session survives. */
  app.post('/api/session/revoke-others', authenticated, async (context) => {
    const revokedSessions = await authentication.revokeUserSessions(
      context.get('authenticatedUser').id,
      { exceptSessionToken: currentSessionToken(context, options.auth) },
    );
    return context.json({ revokedSessions });
  });

  app.post('/api/passkeys/:credentialId/revoke', authenticated, async (context) => {
    const userId = context.get('authenticatedUser').id;
    try {
      const revoked = await authentication.revokeCredential(
        userId,
        context.req.param('credentialId'),
      );
      if (!revoked) {
        return context.json(
          { error: 'passkey_not_found', message: 'The passkey was not found.' },
          404,
        );
      }
      return context.json({ revoked: true });
    } catch (error) {
      if (isLocalWebAuthnError(error) && error.code === 'last_credential') {
        return context.json({ error: 'last_passkey', message: error.message }, 409);
      }
      throw error;
    }
  });

  app.get('/api/health', (context) =>
    context.json({
      status: 'ok',
      service: 'localwebauthn-demo',
    }),
  );

  if (options.staticRoot) {
    app.use('/assets/*', serveStatic({ root: options.staticRoot }));
    const index = serveStatic({ root: options.staticRoot, path: 'index.html' });
    app.get('/', index);
    app.get('/enroll', index);
    app.get('/signup', index);
  }

  app.notFound((context) =>
    context.json({ error: 'not_found', message: 'The resource was not found.' }, 404),
  );
  app.onError((error, context) => {
    console.error(error);
    return context.json(
      { error: 'internal_error', message: 'The request could not be completed.' },
      500,
    );
  });

  return { app, authentication };
}
