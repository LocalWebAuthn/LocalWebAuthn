/**
 * Machine API: issuing client API keys, and authenticating with them.
 *
 * Two route groups with deliberately different shapes.
 *
 * `/api/api-keys/*` is browser-facing. It runs on the ordinary cookie session,
 * demands a *fresh* passkey assertion from a *person*, and hands back
 * registration options carrying `credentialKind: 'service'`. The page generates
 * the key pair itself and never sends the private half.
 *
 * `/api/machine/v1/*` is script-facing. No cookies, no `Origin` check, tokens in
 * the JSON body and the `Authorization` header. It must be mounted *before* the
 * demo's origin-check middleware: a script sends no `Origin`, so that check would
 * reject it. Nothing is lost — CSRF needs the ambient credentials only a browser
 * attaches, and a script has none.
 */

import type {
  AuthenticationVerificationInput,
  RegistrationVerificationInput,
  SessionIdentity,
} from '@localwebauthn/server';
import { isLocalWebAuthnError } from '@localwebauthn/server';
import type { Context, Hono, MiddlewareHandler } from 'hono';
import type { ContentfulStatusCode } from 'hono/utils/http-status';

import type { DemoAuthConfig, DemoAuthentication, DemoEnvironment } from './auth';
import type { DemoDatabase } from './database';

import { currentSessionToken, requireAuthentication } from './auth';
import { listClients } from './database';

/** The `Credential.kind` this demo gives API credentials. */
export const SERVICE_KIND = 'service';

/**
 * How recently a person must have asserted their passkey to mint an API
 * credential. Minting a durable credential is a sensitive credential change, so a
 * live cookie is not enough on its own.
 */
const STEP_UP_MS = 2 * 60_000;

function errorResponse(context: Context<DemoEnvironment>, error: unknown): Response {
  if (!isLocalWebAuthnError(error)) {
    throw error;
  }
  return context.json(
    { error: error.code, message: error.message },
    error.status as ContentfulStatusCode,
  );
}

/**
 * Require a person who asserted their passkey moments ago.
 *
 * Both halves matter. Freshness alone is not a human-presence check: an API
 * credential can produce a fresh assertion at will and would otherwise clear this
 * gate forever — including the gate guarding creation of more API credentials.
 */
async function freshPerson(
  context: Context<DemoEnvironment>,
  authentication: DemoAuthentication,
  config: DemoAuthConfig,
): Promise<{ sessionToken: string; session: SessionIdentity } | Response> {
  const sessionToken = currentSessionToken(context, config);
  const resolved = sessionToken ? await authentication.resolveSession(sessionToken, false) : null;
  if (!sessionToken || !resolved) {
    return context.json(
      { error: 'unauthenticated', message: 'A passkey session is required.' },
      401,
    );
  }
  if (resolved.session.credentialKind !== null) {
    return context.json(
      {
        error: 'forbidden',
        message: 'Only a person may create an API credential.',
      },
      403,
    );
  }
  if (Date.now() - resolved.session.authenticatedAt > STEP_UP_MS) {
    return context.json(
      {
        error: 'reauth_required',
        message: 'Confirm with your passkey to create an API credential.',
      },
      401,
    );
  }
  return { sessionToken, session: resolved.session };
}

/** Browser-facing routes for minting and listing API credentials. */
export function mountApiKeyRoutes(
  app: Hono<DemoEnvironment>,
  authentication: DemoAuthentication,
  config: DemoAuthConfig,
): void {
  const authenticated = requireAuthentication(authentication, config);

  app.get('/api/api-keys', authenticated, async (context) => {
    const userId = context.get('authenticatedUser').id;
    const credentials = await authentication.listCredentials(userId);
    return context.json({
      apiKeys: credentials
        .filter((credential) => credential.kind === SERVICE_KIND)
        .map((credential) => ({
          id: credential.id,
          label: credential.label,
          createdAt: credential.createdAt,
          lastUsedAt: credential.lastUsedAt,
        })),
    });
  });

  app.post('/api/api-keys/options', async (context) => {
    const gate = await freshPerson(context, authentication, config);
    if (gate instanceof Response) {
      return gate;
    }
    try {
      const result = await authentication.registrationOptions({
        sessionToken: gate.sessionToken,
        // Supplied here, by the route that decided to authorize this — never read
        // from the request body, or the client would classify itself.
        credentialKind: SERVICE_KIND,
      });
      return context.json({ options: result.options, challengeToken: result.challengeToken });
    } catch (error) {
      return errorResponse(context, error);
    }
  });

  app.post('/api/api-keys/verify', async (context) => {
    const gate = await freshPerson(context, authentication, config);
    if (gate instanceof Response) {
      return gate;
    }
    type VerifyBody = { response?: unknown; challengeToken?: string; label?: string };
    const body = await context.req.json<VerifyBody>().catch((): VerifyBody => ({}));

    try {
      const result = await authentication.verifyRegistration({
        response: body.response as RegistrationVerificationInput['response'],
        challengeToken: body.challengeToken ?? '',
        sessionToken: gate.sessionToken,
        label: body.label,
      });
      // verifyRegistration opens a session for the *new* credential. That session
      // belongs to the script's identity, not to this browser, so it is dropped
      // rather than returned or set as a cookie.
      return context.json(
        {
          credentialId: result.credentialId,
          credentialKind: result.credentialKind,
        },
        201,
      );
    } catch (error) {
      return errorResponse(context, error);
    }
  });

  app.post('/api/api-keys/:credentialId/revoke', authenticated, async (context) => {
    const userId = context.get('authenticatedUser').id;
    const credentialId = context.req.param('credentialId');
    const credentials = await authentication.listCredentials(userId);
    const target = credentials.find((credential) => credential.id === credentialId);
    if (!target || target.kind !== SERVICE_KIND) {
      return context.json({ error: 'not_found', message: 'No such API credential.' }, 404);
    }
    try {
      // An API credential is never a person's way back in, so removing the last
      // one is not a lockout: the kind-scoped guard would otherwise refuse it.
      await authentication.revokeCredential(userId, credentialId, { allowLastCredential: true });
      return context.json({ revoked: true });
    } catch (error) {
      return errorResponse(context, error);
    }
  });
}

/**
 * Require a live API-credential session proved by a DPoP proof.
 *
 * The proof is verified against the *credential's* public key, so nothing about
 * the key is stored per session; see `packages/server/src/dpop.ts`.
 */
export function requireMachineSession(
  authentication: DemoAuthentication,
): MiddlewareHandler<DemoEnvironment> {
  return async (context, next) => {
    // `Cache-Control: no-store` comes from the shared `/api/*` middleware, which
    // now runs here too — this route group is exempt from its origin check, not
    // from the middleware itself.
    const header = context.req.header('Authorization') ?? '';
    const match = /^(DPoP|Bearer) (?<token>[A-Za-z0-9_-]+)$/u.exec(header);
    const token = match?.groups?.token;
    const resolved = token ? await authentication.resolveSession(token) : null;
    if (!token || !resolved) {
      return context.json(
        { error: 'unauthenticated', message: 'An API session is required.' },
        401,
      );
    }
    if (resolved.session.credentialKind !== SERVICE_KIND) {
      return context.json(
        { error: 'forbidden', message: 'This endpoint requires an API credential.' },
        403,
      );
    }

    try {
      await authentication.verifyDpop({
        proof: context.req.header('DPoP'),
        method: context.req.method,
        url: context.req.url,
        sessionToken: token,
        session: resolved.session,
      });
    } catch (error) {
      return errorResponse(context, error);
    }

    context.set('authenticatedUser', resolved.user);
    context.set('machineSession', resolved.session);
    await next();
  };
}

/**
 * Script-facing routes.
 *
 * Mount before the demo's `/api/*` origin-check middleware.
 */
export function mountMachineRoutes(
  app: Hono<DemoEnvironment>,
  database: DemoDatabase,
  authentication: DemoAuthentication,
): void {
  app.post('/api/machine/v1/login/options', async (context) => {
    try {
      const result = await authentication.authenticationOptions({
        // Names the kind explicitly, so a person's passkey cannot open a session
        // here and a service credential cannot open one at the browser route.
        credentialKinds: [SERVICE_KIND],
      });
      return context.json({
        options: result.options,
        challengeToken: result.challengeToken,
        expiresAt: result.expiresAt,
      });
    } catch (error) {
      return errorResponse(context, error);
    }
  });

  app.post('/api/machine/v1/login/verify', async (context) => {
    type LoginBody = { response?: unknown; challengeToken?: string };
    const body = await context.req.json<LoginBody>().catch((): LoginBody => ({}));
    try {
      const result = await authentication.verifyAuthentication({
        response: body.response as AuthenticationVerificationInput['response'],
        challengeToken: body.challengeToken ?? '',
      });
      return context.json({
        sessionToken: result.sessionToken,
        expiresAt: result.expiresAt,
        credentialId: result.credentialId,
        credentialKind: result.credentialKind,
      });
    } catch (error) {
      return errorResponse(context, error);
    }
  });

  const machine = requireMachineSession(authentication);

  app.get('/api/machine/v1/whoami', machine, (context) => {
    const user = context.get('authenticatedUser');
    const session = context.get('machineSession');
    return context.json({
      userId: user.id,
      name: user.name,
      credentialId: session.credentialId,
      credentialKind: session.credentialKind,
      authenticatedAt: session.authenticatedAt,
      expiresAt: session.expiresAt,
    });
  });

  /** A read-only data endpoint, to have something worth calling. */
  app.get('/api/machine/v1/clients', machine, (context) =>
    context.json({
      clients: listClients(database).map((client) => ({
        id: client.id,
        email: client.email,
        displayName: client.displayName,
        role: client.role,
      })),
    }),
  );
}
