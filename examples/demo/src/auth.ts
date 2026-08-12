import type {
  AuthenticationVerificationInput,
  AuthUser,
  RegistrationVerificationInput,
  SessionIdentity,
} from '@localwebauthn/server';
import {
  authCookieNames,
  cookieAttributes,
  isExactOrigin,
  isLocalWebAuthnError,
  LocalWebAuthn,
} from '@localwebauthn/server';
import { SqliteLocalWebAuthnStore } from '@localwebauthn/server/sqlite';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { Context, Hono, MiddlewareHandler } from 'hono';
import type { ContentfulStatusCode } from 'hono/utils/http-status';

import type { DemoDatabase } from './database';

import {
  bestEffortSignupEventSink,
  passkeyCreatedEmail,
  passkeyCreatedSms,
  type SignupEventSink,
} from '@localwebauthn/channels-core';

import { cancelActiveRecoveries, clientById } from './database';

export type DemoAuthConfig = {
  publicOrigin: string;
  rpId: string;
  rpName: string;
};

export type DemoEnvironment = {
  Variables: {
    authenticatedUser: AuthUser;
    /** Set by `requireMachineSession` on `/api/machine/v1/*` routes. */
    machineSession: SessionIdentity;
  };
};

export type DemoAuthentication = LocalWebAuthn;

type AuthenticationResponse = AuthenticationVerificationInput['response'];
type RegistrationResponse = RegistrationVerificationInput['response'];

/** Local HTTP demo namespace (not `__Host-`; see authCookieNames). */
const cookiesFor = (publicOrigin: string) => authCookieNames(publicOrigin, 'lwa_demo');

export function createDemoAuthentication(
  database: DemoDatabase,
  config: DemoAuthConfig,
  onSignupEvent?: SignupEventSink,
): DemoAuthentication {
  return new LocalWebAuthn({
    rpName: config.rpName,
    rpId: config.rpId,
    expectedOrigins: config.publicOrigin,
    publicOrigin: config.publicOrigin,
    store: new SqliteLocalWebAuthnStore(database),
    // Server-issued DPoP nonces: the one element of a per-request proof the
    // *server* chooses. Everything else in one — jti, iat, htm, htu, the key — is
    // the client's, so this is what stops a key holder pre-generating proofs for
    // later use. Optional in the package; the demo turns it on to exercise it.
    dpopNonce: { rotationMs: 60_000 },
    // Declaring the kind is what turns 'service' from a label into a set of
    // restrictions. An undeclared kind — including null, which every human
    // passkey here has — keeps the default permissive behaviour.
    credentialKinds: {
      service: {
        // Cannot open a session at the browser sign-in route, which never names
        // a kind.
        interactive: false,
        // Cannot enrol another credential. Without this, a leaked .env key mints
        // a spare and outlives revocation of the first.
        canRegister: false,
        // Short sessions: the client re-runs the ceremony on 401, which costs it
        // two round trips and nothing else.
        sessionAbsoluteMs: 15 * 60_000,
      },
    },
    users: {
      getUser: async (userId) => {
        const row = database
          .prepare(
            `SELECT id, email, display_name, active, webauthn_user_handle
             FROM demo_clients
             WHERE id = ?`,
          )
          .get(userId) as
          | {
              id: string;
              email: string;
              display_name: string;
              active: number;
              webauthn_user_handle: Buffer;
            }
          | undefined;
        return row
          ? {
              id: row.id,
              name: row.email,
              displayName: row.display_name,
              active: row.active === 1,
              webAuthnUserHandle: new Uint8Array(row.webauthn_user_handle),
            }
          : null;
      },
    },
    // Signal-style activity veto: a successful passkey sign-in cancels any
    // live self-serve recovery for that person — the owner is present, so
    // nobody (including a channel-compromising attacker) needs re-enrollment.
    // Events are best-effort observability; this is defense in depth on top
    // of the cancel buttons and the recovery delay, not the only control.
    onEvent: async (event) => {
      if (event.type === 'credential.authenticated') {
        await cancelRecoveriesAfterCredentialAuthentication(
          database,
          event.userId,
          Date.now(),
          onSignupEvent,
        );
      }
      // A spent enrollment link was presented again. Either the holder is
      // repeating themselves — bookmark, back button, second device — or somebody
      // else enrolled with it. The server cannot tell those apart; the person can.
      //
      // This is the notify-every-bound-channel step, and it has to happen here
      // rather than in the route: `enrollment.rejected` carries the `userId`, and
      // the thrown error deliberately does not, so that a host cannot leak it into
      // a reply to an unauthenticated caller. A real deployment would send to every
      // channel it has for this person; the demo simulates delivery, so it prints.
      //
      // Only `used` earns a message. `unknown` is what a mangled URL or a probe
      // produces, and notifying on that would notify constantly.
      if (event.type === 'enrollment.rejected' && event.state === 'used' && event.userId) {
        const client = clientById(database, event.userId);
        console.log(
          `[simulated notice] to ${client?.email ?? event.userId}: an enrollment link for ` +
            `your account was presented again after it had already been used. If you did ` +
            `not just do this, contact your administrator.`,
        );
      }
      // A passkey now exists on this account. Tell every channel bound to the
      // person, always.
      //
      // This is the only notice here that does not wait for somebody to notice
      // something. Every other signal is pulled: it reaches the person only if they
      // come back and try something that fails. An attacker who obtains an
      // enrollment link and uses it leaves an account that looks perfectly normal,
      // so a person who never returns is never told. Announcing the credential
      // itself closes that hole, because "a passkey exists" is the state that
      // actually matters.
      //
      // It fires for legitimate enrollments too. That is the design, not a cost:
      // whoever just made a passkey reads it and moves on, and whoever did not reads
      // it and acts. There is no way to know in advance which one is reading.
      if (event.type === 'credential.registered') {
        notifyPasskeyCreated(
          database,
          config,
          event.userId,
          event.credentialKind ?? null,
          event.createdVia,
        );
      }
    },
  });
}

/**
 * Apply the passkey-sign-in veto and report only the recovery rows that changed.
 *
 * The update returns its row identities, so retries and sign-ins with no active
 * recovery emit nothing. Delivery is best-effort because authentication and every
 * cancellation have already committed by the time the core calls this handler.
 */
export async function cancelRecoveriesAfterCredentialAuthentication(
  database: DemoDatabase,
  userId: string,
  canceledAt: number,
  emit?: SignupEventSink,
): Promise<string[]> {
  const signupIds = cancelActiveRecoveries(database, userId, canceledAt);
  if (!emit) {
    return signupIds;
  }
  const bestEffortEmit = bestEffortSignupEventSink(emit, (error, event) => {
    console.warn('Signup event handler failed.', { event: event.type, error });
  });
  for (const signupId of signupIds) {
    await bestEffortEmit({
      type: 'signup.canceled',
      at: canceledAt,
      signupId,
      cause: 'credential_authenticated',
    });
  }
  return signupIds;
}

/**
 * Simulated delivery of {@link passkeyCreatedEmail} / {@link passkeyCreatedSms} to
 * every channel this person has.
 *
 * A real deployment sends these through `channels-node` or `channels-cf` and returns
 * nothing to any caller. The demo prints, exactly as it does for the signup proof
 * messages, so the flow is visible in one terminal.
 */
function notifyPasskeyCreated(
  database: DemoDatabase,
  config: DemoAuthConfig,
  userId: string,
  credentialKind: string | null,
  createdVia: 'enrollment' | 'credential',
): void {
  const client = clientById(database, userId);
  if (!client) {
    return;
  }
  const params = {
    appName: config.rpName,
    // An API credential is worth naming differently: the person minted it from a
    // page they were already signed into, so "passkey" would read as a sign-in
    // credential when it is not one.
    label: credentialKind === null ? 'passkey' : `${credentialKind} credential`,
    createdVia,
    supportContact: 'your administrator',
  };
  const email = passkeyCreatedEmail(params);
  console.log(`[simulated notice] email to ${client.email}: ${email.subject}\n${email.text}`);
  console.log(`[simulated notice] sms to ${client.email}: ${passkeyCreatedSms(params)}`);
}

function setOpaqueCookie(
  context: Context<DemoEnvironment>,
  config: DemoAuthConfig,
  name: string,
  value: string,
  expiresAt: number,
): void {
  setCookie(
    context,
    name,
    value,
    cookieAttributes({ publicOrigin: config.publicOrigin, expiresAt }),
  );
}

function clearOpaqueCookie(
  context: Context<DemoEnvironment>,
  config: DemoAuthConfig,
  name: string,
): void {
  deleteCookie(context, name, cookieAttributes({ publicOrigin: config.publicOrigin }));
}

function authenticationError(context: Context<DemoEnvironment>, error: unknown): Response {
  if (!isLocalWebAuthnError(error)) {
    throw error;
  }
  return context.json(
    {
      error: error.code,
      message: error.message,
      // Why an enrollment link was refused, when the service could say. Present
      // only on `invalid_enrollment`; the browser uses it to choose between "ask
      // for a new link" and the stronger "somebody has already used this one".
      ...(error.enrollmentState ? { enrollmentState: error.enrollmentState } : {}),
    },
    error.status as ContentfulStatusCode,
  );
}

export type OriginCheckOptions = {
  /**
   * Path prefixes whose routes read **no cookie**, and are therefore exempt from
   * the origin check.
   *
   * The precondition is the name: an entry here is only sound if every route
   * beneath it authenticates from the `Authorization` header alone and never
   * falls back to a cookie. CSRF depends on *ambient* credentials — a cookie the
   * browser attaches by itself — so a route that reads none cannot be attacked
   * this way, and there is nothing for the check to defend.
   *
   * The exemption is declared rather than implied by registration order, because
   * order is invisible at the point where it matters. Note also that requiring
   * the header from a non-browser caller would prove nothing: `Origin` is a
   * forbidden request-header, so page JavaScript cannot forge it and a browser's
   * value is trustworthy — but any other client writes whatever string it likes.
   * A check every caller satisfies trivially is worse than a documented absence,
   * because its result can no longer be interpreted.
   */
  cookieFreePrefixes?: string[];
};

/**
 * `Cache-Control: no-store` on every API response, plus an exact-origin check on
 * state-changing requests to cookie-authenticated routes.
 */
export function requireExpectedOrigin(
  config: DemoAuthConfig,
  options: OriginCheckOptions = {},
): MiddlewareHandler<DemoEnvironment> {
  const cookieFreePrefixes = options.cookieFreePrefixes ?? [];
  return async (context, next) => {
    context.header('Cache-Control', 'no-store');
    // Normalize before matching. A raw request line may carry `..` segments, and
    // an exemption decided on the unnormalized path could be claimed by a request
    // that then routes somewhere else entirely. `URL` removes dot segments, so
    // this test sees the same path the router resolves.
    const path = new URL(context.req.url).pathname;
    const cookieFree = cookieFreePrefixes.some((prefix) => path.startsWith(prefix));
    if (
      !cookieFree &&
      context.req.method !== 'GET' &&
      !isExactOrigin(context.req.header('Origin'), config.publicOrigin)
    ) {
      return context.json(
        {
          error: 'invalid_origin',
          message: 'The request origin is not allowed.',
        },
        403,
      );
    }
    await next();
  };
}

/**
 * Raw session token from the request cookie, for routes that act on the
 * caller's own session (e.g. "sign out my other devices").
 */
export function currentSessionToken(
  context: Context<DemoEnvironment>,
  config: DemoAuthConfig,
): string | undefined {
  return getCookie(context, cookiesFor(config.publicOrigin).session);
}

/**
 * Require a live cookie session from an *interactive* credential.
 *
 * The kind check is the load-bearing part, and it is fail-closed for every route
 * that uses this middleware — present and future.
 *
 * A machine credential holds a perfectly valid session token, and nothing stops a
 * script presenting it as a `Cookie` and writing its own `Origin` header. Without
 * the check it would pass here and reach whatever the route does next — including
 * `issueEnrollment`. That matters more than it looks: an enrollment token leads to
 * the *grant* registration path, which carries no `canRegister` gate because it
 * has no authorizing session to inspect, only possession of a single-use token. So
 * a machine that can obtain a grant can register a fresh credential and defeat
 * `canRegister: false` entirely.
 *
 * The rule reuses the kind's own `interactive` declaration rather than adding
 * another switch: a kind that may not *open* a session at the browser login route
 * may not *use* one at a browser route either. One declaration, two enforcement
 * points.
 */
export function requireAuthentication(
  authentication: DemoAuthentication,
  config: DemoAuthConfig,
): MiddlewareHandler<DemoEnvironment> {
  const names = cookiesFor(config.publicOrigin);
  return async (context, next) => {
    const sessionToken = getCookie(context, names.session);
    const resolved = sessionToken ? await authentication.resolveSession(sessionToken) : null;
    if (!resolved) {
      return context.json(
        {
          error: 'unauthenticated',
          message: 'A passkey session is required.',
        },
        401,
      );
    }
    if (!authentication.interactiveKind(resolved.session.credentialKind)) {
      return context.json(
        {
          error: 'forbidden',
          message: 'This endpoint requires an interactive credential.',
        },
        403,
      );
    }
    context.set('authenticatedUser', resolved.user);
    await next();
  };
}

export function mountAuthenticationRoutes(
  app: Hono<DemoEnvironment>,
  authentication: DemoAuthentication,
  config: DemoAuthConfig,
): void {
  const names = cookiesFor(config.publicOrigin);

  app.post('/api/auth/enrollment/exchange', async (context) => {
    const body = await context.req.json<{ token?: string }>().catch((): { token?: string } => ({}));
    try {
      const result = await authentication.exchangeEnrollment(body.token ?? '');
      setOpaqueCookie(
        context,
        config,
        names.enrollment,
        result.enrollmentSessionToken,
        result.expiresAt,
      );
      return context.json(result.user);
    } catch (error) {
      return authenticationError(context, error);
    }
  });

  app.post('/api/auth/register/options', async (context) => {
    try {
      const result = await authentication.registrationOptions({
        enrollmentSessionToken: getCookie(context, names.enrollment),
        sessionToken: getCookie(context, names.session),
      });
      setOpaqueCookie(context, config, names.challenge, result.challengeToken, result.expiresAt);
      return context.json(result.options);
    } catch (error) {
      return authenticationError(context, error);
    }
  });

  app.post('/api/auth/register/verify', async (context) => {
    const body = await context.req
      .json<Record<string, unknown>>()
      .catch((): Record<string, unknown> => ({}));
    const label = typeof body.localWebAuthnLabel === 'string' ? body.localWebAuthnLabel : undefined;
    const response = { ...body };
    delete response.localWebAuthnLabel;
    const challengeToken = getCookie(context, names.challenge) ?? '';
    clearOpaqueCookie(context, config, names.challenge);

    try {
      const result = await authentication.verifyRegistration({
        response: response as unknown as RegistrationResponse,
        challengeToken,
        enrollmentSessionToken: getCookie(context, names.enrollment),
        sessionToken: getCookie(context, names.session),
        label,
      });
      clearOpaqueCookie(context, config, names.enrollment);
      setOpaqueCookie(context, config, names.session, result.sessionToken, result.expiresAt);
      return context.json({ verified: true }, 201);
    } catch (error) {
      return authenticationError(context, error);
    }
  });

  app.post('/api/auth/login/options', async (context) => {
    try {
      const result = await authentication.authenticationOptions();
      setOpaqueCookie(context, config, names.challenge, result.challengeToken, result.expiresAt);
      return context.json(result.options);
    } catch (error) {
      return authenticationError(context, error);
    }
  });

  app.post('/api/auth/login/verify', async (context) => {
    const response = await context.req.json<unknown>().catch(() => ({}));
    const challengeToken = getCookie(context, names.challenge) ?? '';
    clearOpaqueCookie(context, config, names.challenge);

    try {
      const result = await authentication.verifyAuthentication({
        response: response as AuthenticationResponse,
        challengeToken,
      });
      setOpaqueCookie(context, config, names.session, result.sessionToken, result.expiresAt);
      return context.json({ verified: true });
    } catch (error) {
      return authenticationError(context, error);
    }
  });

  app.post('/api/auth/logout', async (context) => {
    const sessionToken = getCookie(context, names.session);
    if (sessionToken) {
      await authentication.revokeSession(sessionToken);
    }
    clearOpaqueCookie(context, config, names.session);
    return context.json({ signed_out: true });
  });
}
