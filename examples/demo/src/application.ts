import type { EnrollmentIssue } from '@localwebauthn/server';
import { createUserHandle, isLocalWebAuthnError } from '@localwebauthn/server';
import { serveStatic } from '@hono/node-server/serve-static';
import { Hono } from 'hono';
import type { MiddlewareHandler } from 'hono';
import { randomUUID } from 'node:crypto';

import type { DemoAuthConfig, DemoAuthentication, DemoEnvironment } from './auth';
import type { DemoClient, DemoDatabase } from './database';

import {
  createDemoAuthentication,
  mountAuthenticationRoutes,
  requireAuthentication,
  requireExpectedOrigin,
} from './auth';
import { clientByEmail, clientById, listClients } from './database';

export type DemoApplicationOptions = {
  auth: DemoAuthConfig;
  staticRoot?: string;
};

type ClientPayload = DemoClient & {
  passkeyCount: number;
};

function validEmail(email: string): boolean {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/u.test(email);
}

async function clientPayload(
  client: DemoClient,
  authentication: DemoAuthentication,
): Promise<ClientPayload> {
  return {
    ...client,
    passkeyCount: (await authentication.listCredentials(client.id)).length,
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

export function createDemoApplication(database: DemoDatabase, options: DemoApplicationOptions) {
  const app = new Hono<DemoEnvironment>();
  const authentication = createDemoAuthentication(database, options.auth);

  app.use('/api/*', requireExpectedOrigin(options.auth));
  mountAuthenticationRoutes(app, authentication, options.auth);

  const authenticated = requireAuthentication(authentication);
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
