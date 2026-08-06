import { serve } from '@hono/node-server';
import { LocalWebAuthn, signupPhase } from '@localwebauthn/server';
import { SqliteLocalWebAuthnStore } from '@localwebauthn/server/sqlite';
import { Hono } from 'hono';
import { randomUUID } from 'node:crypto';

import { mountPasskeyAuth, requireSession, type StarterEnv } from './auth-routes';
import {
  ensureUser,
  getUser,
  getUserByEmail,
  hasPendingEnrollment,
  openDatabase,
  setPendingEnrollment,
} from './db';

const publicOrigin = process.env.STARTER_PUBLIC_ORIGIN ?? 'http://localhost:4180';
const origin = new URL(publicOrigin);
const port = Number(process.env.STARTER_PORT ?? (origin.port || '4180'));
const config = { publicOrigin: origin.origin };

const database = openDatabase();
const auth = new LocalWebAuthn({
  rpName: 'LocalWebAuthn Hono Starter',
  rpId: origin.hostname,
  expectedOrigins: origin.origin,
  publicOrigin: origin.origin,
  store: new SqliteLocalWebAuthnStore(database),
  users: {
    getUser: async (userId) => {
      const user = getUser(database, userId);
      return user
        ? {
            id: user.id,
            name: user.email,
            displayName: user.displayName,
            active: user.active,
            webAuthnUserHandle: user.webAuthnUserHandle,
          }
        : null;
    },
  },
});

const bootstrapId = process.env.STARTER_BOOTSTRAP_ID ?? 'bootstrap-admin';
ensureUser(database, {
  id: bootstrapId,
  email: process.env.STARTER_BOOTSTRAP_EMAIL ?? 'admin@example.test',
  displayName: process.env.STARTER_BOOTSTRAP_NAME ?? 'Starter Admin',
});

// Signup state machine: only issue a grant when the user is still "created" or
// we are re-bootstrapping with zero credentials.
const credentials = await auth.listCredentials(bootstrapId);
let bootstrapUrl: string | null = null;
if (credentials.length === 0) {
  const issue = await auth.issueEnrollment(bootstrapId);
  setPendingEnrollment(database, bootstrapId, true);
  bootstrapUrl = issue.enrollmentUrl;
  const phase = signupPhase({
    hasActiveCredential: false,
    hasPendingEnrollmentGrant: hasPendingEnrollment(database, bootstrapId),
    hasEnrollmentSession: false,
  });
  console.log(`Bootstrap signup phase: ${phase}`);
} else {
  setPendingEnrollment(database, bootstrapId, false);
}

const app = new Hono<StarterEnv>();
mountPasskeyAuth(app, auth, config);

app.get('/api/health', (c) => c.json({ status: 'ok', service: 'localwebauthn-starter-hono' }));

app.get('/api/me', requireSession(auth, config), async (c) => {
  const user = c.get('user');
  const passkeys = await auth.listCredentials(user.id);
  const phase = signupPhase({
    hasActiveCredential: passkeys.length > 0,
    hasPendingEnrollmentGrant: hasPendingEnrollment(database, user.id),
    hasEnrollmentSession: false,
  });
  return c.json({
    user: { id: user.id, name: user.name, displayName: user.displayName },
    passkeyCount: passkeys.length,
    signupPhase: phase,
  });
});

// Example of host-owned signup: create user + issue grant (no channel proof here).
//
// AUTHORIZATION IS YOURS: every signed-in session may invite here. A real
// application must add its own role check (see the demo's `administrator`
// middleware) and rate limiting before exposing this route.
app.post('/api/invite', requireSession(auth, config), async (c) => {
  const body = await c.req
    .json<{ email?: string; displayName?: string }>()
    .catch((): { email?: string; displayName?: string } => ({}));
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const displayName = typeof body.displayName === 'string' ? body.displayName.trim() : '';
  if (!email || !displayName) {
    return c.json({ error: 'invalid_invite', message: 'email and displayName are required.' }, 400);
  }
  if (getUserByEmail(database, email)) {
    return c.json({ error: 'email_exists', message: 'That email is already invited.' }, 409);
  }
  const id = randomUUID();
  ensureUser(database, { id, email, displayName });
  const enrollment = await auth.issueEnrollment(id, c.get('user').id);
  setPendingEnrollment(database, id, true);
  const phase = signupPhase({
    hasActiveCredential: false,
    hasPendingEnrollmentGrant: true,
    hasEnrollmentSession: false,
  });
  return c.json(
    {
      userId: id,
      enrollmentUrl: enrollment.enrollmentUrl,
      expiresAt: enrollment.expiresAt,
      signupPhase: phase,
    },
    201,
  );
});

serve({ fetch: app.fetch, hostname: '127.0.0.1', port }, (info) => {
  console.log(`Hono starter listening on http://${info.address}:${String(info.port)}`);
  if (bootstrapUrl) {
    console.log('');
    console.log('Bootstrap enrollment URL (open, then create a passkey):');
    console.log(bootstrapUrl);
  } else {
    console.log('Bootstrap user already has a passkey; POST /api/invite when signed in.');
  }
});
