import type { EnrollmentIssue } from '@localwebauthn/server';
import {
  createUserHandle,
  describeSignupPhase,
  isLocalWebAuthnError,
  provisioningPageHeaders,
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
  canCancelSignup,
  createSignupChallenge,
  signupMissing,
  signupProofEmail,
  signupProofSms,
  signupProofUrl,
  signupSatisfied,
  verifySignupProof,
  type SignupEvent,
  type SignupEventSink,
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
  cancelSignup,
  clientByEmail,
  clientById,
  completeSignup,
  countSignupClaim,
  insertSignup,
  listClients,
  markSignupPending,
  markSignupProved,
  signupById,
  storeSignupClaim,
} from './database';
import { mountApiKeyRoutes, mountMachineRoutes } from './machine';

export type DemoApplicationOptions = {
  auth: DemoAuthConfig;
  staticRoot?: string;
  /**
   * Recovery waiting period before a completed re-enrollment becomes
   * claimable. Real deployments use hours or days; the demo defaults to ten
   * seconds so the flow is watchable.
   */
  recoveryDelayMs?: number;
  /** How long a matured recovery claim stays available. */
  recoveryClaimWindowMs?: number;
  /**
   * Where signup lifecycle events go.
   *
   * The proofing machine is entirely host-owned, so `@localwebauthn/server`'s
   * `onEvent` never sees any of it — its first sight of a self-serve flow is
   * `enrollment.issued`, at completion. Without a sink here, starting a signup,
   * proving a channel, presenting a wrong OTP and vetoing are all invisible, and
   * since expired rows are now reaped there is afterwards no record they happened.
   *
   * Defaults to `console.log`, so the demo shows the trail in the same terminal as
   * the simulated messages.
   */
  onSignupEvent?: SignupEventSink;
};

/**
 * Where signup events go when the host names no sink.
 *
 * A real deployment sends these to whatever it uses for audit — structured logs, an
 * events table, a SIEM. Printing is the demo's equivalent, and it deliberately prints
 * the whole event: none of these carry an OTP, an enrollment token, an email address
 * or a phone number, so a log is a safe destination for all of them.
 */
function defaultSignupEventSink(event: SignupEvent): void {
  console.log(`[signup] ${JSON.stringify(event)}`);
}

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
  // Interactive credentials only: the administrator table's "Passkeys" column and
  // the signup phase both mean "can this person sign in", which an API credential
  // cannot do.
  const passkeyCount = (await authentication.listCredentials(client.id)).filter((credential) =>
    authentication.interactiveKind(credential.kind),
  ).length;
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
    canceledAt: signup.canceledAt,
    claimableAt: signup.claimableAt,
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
  delays: { recoveryDelayMs: number; recoveryClaimWindowMs: number },
  emit: SignupEventSink,
): void {
  /**
   * First mature claim of a completed recovery: only here — after the waiting
   * period passed uncanceled — does the account change. Revoke-then-issue,
   * store the token so every channel's link claims the same one. (Demo-grade
   * concurrency: better-sqlite3 serializes statements in-process.)
   */
  async function claimEnrollment(signupId: string): Promise<Response | string> {
    const signup = signupById(database, signupId);
    if (!signup) {
      return 'missing';
    }
    // Either kind: a stored token means this signup's claim already happened, so
    // hand back the same one. Keeping it identical is what lets a spent link report
    // `used` rather than the reassuring `superseded`.
    if (signup.enrollmentToken) {
      // Counting here, not at completion: this is the branch every reopen takes, so
      // it is the only place an extra claim can be seen.
      emit({
        type: 'signup.claimed',
        at: Date.now(),
        signupId: signup.id,
        claimCount: countSignupClaim(database, signup.id),
      });
      return signup.enrollmentToken;
    }
    // Below this line the account gets restructured, so the kind is checked
    // explicitly rather than inferred.
    //
    // This function serves both kinds, because `verifySignupProof` reports
    // `'completed'` for both. It used to tell them apart only by whether a token
    // happened to be stored — plain signup stores one at completion, recovery does
    // not until its first mature claim — which made an account-wide revoke
    // reachable by accident. Any change that left the column empty on a plain
    // signup would have revoked a person's passkeys because they re-opened their
    // own link. Revocation is not something to arrive at implicitly.
    if (signup.kind !== 'recovery') {
      // A completed plain signup always stores its token in the same statement
      // that marks it consumed, so this is a bug rather than a state to recover
      // from. Say so instead of issuing anything.
      return 'incomplete';
    }
    const existing = clientByEmail(database, signup.email);
    if (existing?.role === 'administrator') {
      return 'administrator';
    }
    if (!existing) {
      // Recovery presupposes an account — `kind` is only `'recovery'` when one
      // existed at signup start. Creating one here would turn a recovery into a
      // silent signup for whatever address the row happens to hold.
      return 'incomplete';
    }
    // The one revoke in this flow, and the only place it belongs: recovery means
    // "replace my credentials". It is gated by the delay, the veto from any
    // channel, and cancel-on-passkey-sign-in, all applied before this runs.
    await authentication.revokeUserAuthentication(existing.id);
    const enrollment = await authentication.issueEnrollment(existing.id);
    storeSignupClaim(database, signup.id, {
      clientId: existing.id,
      enrollmentToken: enrollment.enrollmentToken,
    });
    emit({
      type: 'signup.claimed',
      at: Date.now(),
      signupId: signup.id,
      claimCount: countSignupClaim(database, signup.id),
    });
    return signupById(database, signup.id)?.enrollmentToken ?? enrollment.enrollmentToken;
  }
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

    const kind = existing ? 'recovery' : 'signup';
    const challenge = await createSignupChallenge(SIGNUP_CHANNELS);
    insertSignup(database, {
      id: challenge.signupId,
      email,
      phone,
      displayName: existing?.displayName ?? displayName,
      kind,
      otpEmailHash: challenge.otpHashes.email,
      otpPhoneHash: challenge.otpHashes.phone,
      expiresAt: challenge.expiresAt,
    });

    emit({
      type: 'signup.started',
      at: Date.now(),
      signupId: challenge.signupId,
      kind,
      channels: [...SIGNUP_CHANNELS],
    });

    const appName = config.rpName;
    const recovery = kind === 'recovery';
    const emailUrl = signupProofUrl(
      config.publicOrigin,
      challenge.signupId,
      'email',
      challenge.otps.email,
      undefined,
      { recovery },
    );
    const phoneUrl = signupProofUrl(
      config.publicOrigin,
      challenge.signupId,
      'phone',
      challenge.otps.phone,
      undefined,
      { recovery },
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
    // Reported before any branch below, so a rejected proof is as visible as an
    // accepted one. A run of `invalid` against one signup is somebody guessing, and
    // that is the single most useful thing in this stream.
    emit({ type: 'signup.proof', at: now, signupId: signup.id, channel, outcome });
    const identity = { name: signup.email, displayName: signup.displayName };

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
    if (outcome === 'canceled') {
      return context.json({ complete: false, canceled: true });
    }
    if (outcome === 'pending') {
      return context.json({
        complete: false,
        pending: true,
        claimableAt: signup.claimableAt,
        kind: signup.kind,
      });
    }
    if (outcome === 'completed') {
      // Claim-on-reopen: any proved channel's link opens enrollment. For a
      // matured recovery, the first claim performs revoke-then-issue here.
      const claimed = await claimEnrollment(signup.id);
      if (claimed === 'administrator') {
        return context.json(
          { error: 'not_self_serve', message: 'This account cannot use self-serve signup.' },
          409,
        );
      }
      if (claimed === 'missing') {
        return context.json(
          { error: 'invalid_proof', message: 'This confirmation link is not valid.' },
          403,
        );
      }
      if (claimed === 'incomplete') {
        // A state that should not arise. Refusing loudly beats improvising: the
        // improvisation on offer here would be to revoke somebody's credentials.
        return context.json(
          {
            error: 'signup_incomplete',
            message: 'This signup did not finish correctly. Ask for a new invitation.',
          },
          409,
        );
      }
      return context.json({ complete: true, enrollmentToken: claimed, user: identity });
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
        kind: signup.kind,
      });
    }

    if (signup.kind === 'recovery') {
      // Recovery is not signup: completion opens a waiting period during
      // which the account is untouched, every open proof page shows the
      // countdown with a cancel, and any passkey sign-in vetoes the whole
      // thing. Real hosts also notify every channel here.
      const claimableAt = now + delays.recoveryDelayMs;
      markSignupPending(database, signup.id, {
        claimableAt,
        expiresAt: claimableAt + delays.recoveryClaimWindowMs,
        now,
      });
      emit({
        type: 'signup.completed',
        at: now,
        signupId: signup.id,
        kind: signup.kind,
        userId: null,
      });
      emit({ type: 'signup.pending', at: now, signupId: signup.id, claimableAt });
      return context.json({ complete: false, pending: true, claimableAt, kind: signup.kind });
    }

    // Plain signup: no prior credentials, no waiting period. Only now does
    // the enrollment grant come to exist.
    const clientId = randomUUID();
    database
      .prepare(
        `INSERT INTO demo_clients(
           id, email, display_name, role, webauthn_user_handle, created_at
         ) VALUES (?, ?, ?, 'client', ?, ?)`,
      )
      .run(clientId, signup.email, signup.displayName, createUserHandle(), now);
    const enrollment = await authentication.issueEnrollment(clientId);
    completeSignup(database, signup.id, {
      clientId,
      enrollmentToken: enrollment.enrollmentToken,
      now,
    });
    emit({
      type: 'signup.completed',
      at: now,
      signupId: signup.id,
      kind: signup.kind,
      userId: clientId,
    });
    // The completing browser is handed the token directly, so this is a claim too —
    // the first one. Counting it here keeps `claimCount` honest: a later reopen
    // reports 2, which is what makes an extra claim distinguishable.
    emit({
      type: 'signup.claimed',
      at: now,
      signupId: signup.id,
      claimCount: countSignupClaim(database, signup.id),
    });
    return context.json({
      complete: true,
      enrollmentToken: enrollment.enrollmentToken,
      user: identity,
    });
  });

  /**
   * The veto: any valid channel OTP cancels, terminally, from any state —
   * before completion, during the recovery waiting period, even after a
   * plain-signup completion (harmless once the token was claimed). A false
   * cancel costs a restart; a false confirm could cost the account.
   */
  app.post('/api/signup/cancel', async (context) => {
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
    const outcome = await verifySignupProof(signupProofState(signup), { channel, otp }, Date.now());
    if (!canCancelSignup(outcome)) {
      return context.json(
        { error: 'invalid_proof', message: 'This confirmation link is not valid.' },
        outcome === 'expired' ? 410 : 403,
      );
    }
    const canceledAt = Date.now();
    cancelSignup(database, signup.id, canceledAt);
    emit({ type: 'signup.canceled', at: canceledAt, signupId: signup.id });
    return context.json({ canceled: true });
  });
}

export function createDemoApplication(database: DemoDatabase, options: DemoApplicationOptions) {
  const app = new Hono<DemoEnvironment>();
  const authentication = createDemoAuthentication(database, options.auth);

  // `/api/machine/*` routes authenticate from the `Authorization` header and read
  // no cookie, so CSRF cannot reach them and the origin check has nothing to
  // defend — see `cookieFreePrefixes`. Declaring the exemption here means route
  // registration order below carries no security weight.
  app.use('/api/*', requireExpectedOrigin(options.auth, { cookieFreePrefixes: ['/api/machine/'] }));
  mountAuthenticationRoutes(app, authentication, options.auth);
  mountApiKeyRoutes(app, authentication, options.auth);
  mountMachineRoutes(app, database, authentication);
  mountSignupRoutes(
    app,
    database,
    authentication,
    options.auth,
    {
      recoveryDelayMs: options.recoveryDelayMs ?? 10_000,
      recoveryClaimWindowMs: options.recoveryClaimWindowMs ?? 15 * 60_000,
    },
    options.onSignupEvent ?? defaultSignupEventSink,
  );

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
      // Interactive kinds only. An API credential belongs in its own section, and
      // rendering one here would show it as "Device-bound · Last used", which is
      // exactly the mislabelling the `kind` column exists to prevent — and would
      // also offer a revoke button under the wrong heading.
      passkeys: (await authentication.listCredentials(current.id))
        .filter((credential) => authentication.interactiveKind(credential.kind))
        .map((credential) => ({
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
      const enrollment = await authentication.issueEnrollment(id, {
        approvedByUserId: context.get('authenticatedUser').id,
      });
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
    const enrollment = await authentication.issueEnrollment(client.id, {
      approvedByUserId: context.get('authenticatedUser').id,
    });
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
    const enrollment = await authentication.issueEnrollment(client.id, {
      approvedByUserId: context.get('authenticatedUser').id,
    });
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
    // The single-page app displays a freshly minted API credential's private key,
    // so the document that carries it gets the show-once hardening: a CSP with no
    // inline script, no framing, no caching, no referrer. One injected script tag
    // on this page could read the key straight out of the DOM, and headers are the
    // only thing standing between "our bundle" and "any bundle".
    //
    // This app is one origin for both the admin UI and the mint panel, which is a
    // demo simplification: in production, serve a provisioning page from its own
    // minimal origin so its attack surface is not the whole application's.
    app.use('/assets/*', async (context, next) => {
      await next();
      for (const [header, value] of Object.entries(provisioningPageHeaders())) {
        context.header(header, value);
      }
    });
    app.use('/assets/*', serveStatic({ root: options.staticRoot }));

    const index = serveStatic({ root: options.staticRoot, path: 'index.html' });
    const hardenedIndex: MiddlewareHandler<DemoEnvironment> = async (context, next) => {
      for (const [header, value] of Object.entries(provisioningPageHeaders())) {
        context.header(header, value);
      }
      return index(context, next);
    };
    app.get('/', hardenedIndex);
    app.get('/enroll', hardenedIndex);
    app.get('/signup', hardenedIndex);
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
