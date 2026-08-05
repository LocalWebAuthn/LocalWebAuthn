import type {
  AuthenticationVerificationInput,
  AuthUser,
  RegistrationVerificationInput,
} from '@localwebauthn/server';
import { isLocalWebAuthnError, LocalWebAuthn } from '@localwebauthn/server';
import { SqliteLocalWebAuthnStore } from '@localwebauthn/server/sqlite';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { Context, Hono, MiddlewareHandler } from 'hono';
import type { ContentfulStatusCode } from 'hono/utils/http-status';

import type { DemoDatabase } from './database';

export type DemoAuthConfig = {
  publicOrigin: string;
  rpId: string;
  rpName: string;
};

export type DemoEnvironment = {
  Variables: {
    authenticatedUser: AuthUser;
  };
};

export type DemoAuthentication = LocalWebAuthn;

type AuthenticationResponse = AuthenticationVerificationInput['response'];
type RegistrationResponse = RegistrationVerificationInput['response'];

const CHALLENGE_COOKIE = 'localwebauthn_demo_challenge';
const ENROLLMENT_COOKIE = 'localwebauthn_demo_enrollment';
const SESSION_COOKIE = 'localwebauthn_demo_session';

export function createDemoAuthentication(
  database: DemoDatabase,
  config: DemoAuthConfig,
): DemoAuthentication {
  return new LocalWebAuthn({
    rpName: config.rpName,
    rpId: config.rpId,
    expectedOrigins: config.publicOrigin,
    publicOrigin: config.publicOrigin,
    store: new SqliteLocalWebAuthnStore(database),
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
  });
}

function cookieOptions(config: DemoAuthConfig, expiresAt?: number) {
  return {
    httpOnly: true,
    path: '/',
    sameSite: 'Strict' as const,
    secure: new URL(config.publicOrigin).protocol === 'https:',
    ...(expiresAt ? { maxAge: Math.max(1, Math.ceil((expiresAt - Date.now()) / 1000)) } : {}),
  };
}

function setOpaqueCookie(
  context: Context<DemoEnvironment>,
  config: DemoAuthConfig,
  name: string,
  value: string,
  expiresAt: number,
): void {
  setCookie(context, name, value, cookieOptions(config, expiresAt));
}

function clearOpaqueCookie(
  context: Context<DemoEnvironment>,
  config: DemoAuthConfig,
  name: string,
): void {
  deleteCookie(context, name, cookieOptions(config));
}

function authenticationError(context: Context<DemoEnvironment>, error: unknown): Response {
  if (!isLocalWebAuthnError(error)) {
    throw error;
  }
  return context.json(
    {
      error: error.code,
      message: error.message,
    },
    error.status as ContentfulStatusCode,
  );
}

export function requireExpectedOrigin(config: DemoAuthConfig): MiddlewareHandler<DemoEnvironment> {
  return async (context, next) => {
    context.header('Cache-Control', 'no-store');
    if (context.req.method !== 'GET' && context.req.header('Origin') !== config.publicOrigin) {
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
export function currentSessionToken(context: Context<DemoEnvironment>): string | undefined {
  return getCookie(context, SESSION_COOKIE);
}

export function requireAuthentication(
  authentication: DemoAuthentication,
): MiddlewareHandler<DemoEnvironment> {
  return async (context, next) => {
    const sessionToken = getCookie(context, SESSION_COOKIE);
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
    context.set('authenticatedUser', resolved.user);
    await next();
  };
}

export function mountAuthenticationRoutes(
  app: Hono<DemoEnvironment>,
  authentication: DemoAuthentication,
  config: DemoAuthConfig,
): void {
  app.post('/api/auth/enrollment/exchange', async (context) => {
    const body = await context.req.json<{ token?: string }>().catch((): { token?: string } => ({}));
    try {
      const result = await authentication.exchangeEnrollment(body.token ?? '');
      setOpaqueCookie(
        context,
        config,
        ENROLLMENT_COOKIE,
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
        enrollmentSessionToken: getCookie(context, ENROLLMENT_COOKIE),
        sessionToken: getCookie(context, SESSION_COOKIE),
      });
      setOpaqueCookie(context, config, CHALLENGE_COOKIE, result.challengeToken, result.expiresAt);
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
    const challengeToken = getCookie(context, CHALLENGE_COOKIE) ?? '';
    clearOpaqueCookie(context, config, CHALLENGE_COOKIE);

    try {
      const result = await authentication.verifyRegistration({
        response: response as unknown as RegistrationResponse,
        challengeToken,
        enrollmentSessionToken: getCookie(context, ENROLLMENT_COOKIE),
        sessionToken: getCookie(context, SESSION_COOKIE),
        label,
      });
      clearOpaqueCookie(context, config, ENROLLMENT_COOKIE);
      setOpaqueCookie(context, config, SESSION_COOKIE, result.sessionToken, result.expiresAt);
      return context.json({ verified: true }, 201);
    } catch (error) {
      return authenticationError(context, error);
    }
  });

  app.post('/api/auth/login/options', async (context) => {
    try {
      const result = await authentication.authenticationOptions();
      setOpaqueCookie(context, config, CHALLENGE_COOKIE, result.challengeToken, result.expiresAt);
      return context.json(result.options);
    } catch (error) {
      return authenticationError(context, error);
    }
  });

  app.post('/api/auth/login/verify', async (context) => {
    const response = await context.req.json<unknown>().catch(() => ({}));
    const challengeToken = getCookie(context, CHALLENGE_COOKIE) ?? '';
    clearOpaqueCookie(context, config, CHALLENGE_COOKIE);

    try {
      const result = await authentication.verifyAuthentication({
        response: response as AuthenticationResponse,
        challengeToken,
      });
      setOpaqueCookie(context, config, SESSION_COOKIE, result.sessionToken, result.expiresAt);
      return context.json({ verified: true });
    } catch (error) {
      return authenticationError(context, error);
    }
  });

  app.post('/api/auth/logout', async (context) => {
    const sessionToken = getCookie(context, SESSION_COOKIE);
    if (sessionToken) {
      await authentication.revokeSession(sessionToken);
    }
    clearOpaqueCookie(context, config, SESSION_COOKIE);
    return context.json({ signed_out: true });
  });
}
