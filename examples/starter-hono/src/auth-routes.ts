import type { AuthUser, LocalWebAuthn } from '@localwebauthn/server';
import {
  authCookieNames,
  cookieAttributes,
  isExactOrigin,
  isLocalWebAuthnError,
} from '@localwebauthn/server';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { Context, Hono, MiddlewareHandler } from 'hono';
import type { ContentfulStatusCode } from 'hono/utils/http-status';

export type StarterEnv = {
  Variables: {
    user: AuthUser;
  };
};

export type StarterConfig = {
  publicOrigin: string;
};

/**
 * Drop-in six-route adapter for `@localwebauthn/browser` defaults.
 * Copy this file into an application and adjust cookie namespace if needed.
 */
export function mountPasskeyAuth(
  app: Hono<StarterEnv>,
  auth: LocalWebAuthn,
  config: StarterConfig,
): void {
  const names = authCookieNames(config.publicOrigin);
  const attrs = (expiresAt?: number) =>
    cookieAttributes({ publicOrigin: config.publicOrigin, expiresAt });

  const set = (c: Context<StarterEnv>, name: string, value: string, expiresAt: number) => {
    setCookie(c, name, value, attrs(expiresAt));
  };
  const clear = (c: Context<StarterEnv>, name: string) => {
    deleteCookie(c, name, attrs());
  };
  const fail = (c: Context<StarterEnv>, error: unknown) => {
    if (!isLocalWebAuthnError(error)) {
      throw error;
    }
    return c.json(
      { error: error.code, message: error.message },
      error.status as ContentfulStatusCode,
    );
  };

  app.use('/api/*', async (c, next) => {
    c.header('Cache-Control', 'no-store');
    if (c.req.method !== 'GET' && !isExactOrigin(c.req.header('Origin'), config.publicOrigin)) {
      return c.json(
        { error: 'invalid_origin', message: 'The request origin is not allowed.' },
        403,
      );
    }
    await next();
  });

  app.post('/api/auth/enrollment/exchange', async (c) => {
    try {
      const body = await c.req.json<{ token?: string }>().catch((): { token?: string } => ({}));
      const result = await auth.exchangeEnrollment(body.token ?? '');
      set(c, names.enrollment, result.enrollmentSessionToken, result.expiresAt);
      return c.json(result.user);
    } catch (error) {
      return fail(c, error);
    }
  });

  app.post('/api/auth/register/options', async (c) => {
    try {
      const result = await auth.registrationOptions({
        enrollmentSessionToken: getCookie(c, names.enrollment),
        sessionToken: getCookie(c, names.session),
      });
      set(c, names.challenge, result.challengeToken, result.expiresAt);
      return c.json(result.options);
    } catch (error) {
      return fail(c, error);
    }
  });

  app.post('/api/auth/register/verify', async (c) => {
    const body = await c.req
      .json<Record<string, unknown>>()
      .catch((): Record<string, unknown> => ({}));
    const label = typeof body.localWebAuthnLabel === 'string' ? body.localWebAuthnLabel : undefined;
    const response = { ...body };
    delete response.localWebAuthnLabel;
    const challengeToken = getCookie(c, names.challenge) ?? '';
    clear(c, names.challenge);
    try {
      const result = await auth.verifyRegistration({
        response: response as never,
        challengeToken,
        enrollmentSessionToken: getCookie(c, names.enrollment),
        sessionToken: getCookie(c, names.session),
        label,
      });
      clear(c, names.enrollment);
      set(c, names.session, result.sessionToken, result.expiresAt);
      return c.json({ verified: true }, 201);
    } catch (error) {
      return fail(c, error);
    }
  });

  app.post('/api/auth/login/options', async (c) => {
    try {
      const result = await auth.authenticationOptions();
      set(c, names.challenge, result.challengeToken, result.expiresAt);
      return c.json(result.options);
    } catch (error) {
      return fail(c, error);
    }
  });

  app.post('/api/auth/login/verify', async (c) => {
    const response = await c.req.json<unknown>().catch(() => ({}));
    const challengeToken = getCookie(c, names.challenge) ?? '';
    clear(c, names.challenge);
    try {
      const result = await auth.verifyAuthentication({
        response: response as never,
        challengeToken,
      });
      set(c, names.session, result.sessionToken, result.expiresAt);
      return c.json({ verified: true, user: result.user });
    } catch (error) {
      return fail(c, error);
    }
  });

  app.post('/api/auth/logout', async (c) => {
    const token = getCookie(c, names.session);
    if (token) {
      await auth.revokeSession(token);
    }
    clear(c, names.session);
    return c.json({ signed_out: true });
  });
}

export function requireSession(
  auth: LocalWebAuthn,
  config: StarterConfig,
): MiddlewareHandler<StarterEnv> {
  const names = authCookieNames(config.publicOrigin);
  return async (c, next) => {
    const token = getCookie(c, names.session);
    const resolved = token ? await auth.resolveSession(token) : null;
    if (!resolved) {
      return c.json({ error: 'unauthenticated', message: 'A passkey session is required.' }, 401);
    }
    c.set('user', resolved.user);
    await next();
  };
}
