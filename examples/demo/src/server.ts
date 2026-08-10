import { serve } from '@hono/node-server';

import { createDemoApplication, ensureBootstrapAdministrator } from './application';
import { openDemoDatabase, reapSignups } from './database';

const publicOrigin = process.env.DEMO_PUBLIC_ORIGIN ?? 'http://localhost:4173';
const origin = new URL(publicOrigin);
const port = Number(process.env.DEMO_PORT ?? (origin.port || '4173'));
const database = openDemoDatabase();
const { app, authentication } = createDemoApplication(database, {
  auth: {
    publicOrigin: origin.origin,
    rpId: origin.hostname,
    rpName: 'LocalWebAuthn Demo',
  },
  staticRoot: 'dist',
});
const bootstrap = await ensureBootstrapAdministrator(database, authentication, {
  email: process.env.DEMO_BOOTSTRAP_EMAIL ?? 'admin@example.test',
  displayName: process.env.DEMO_BOOTSTRAP_NAME ?? 'Demo Administrator',
});

const server = serve(
  {
    fetch: app.fetch,
    hostname: '127.0.0.1',
    port,
  },
  (info) => {
    console.log(`LocalWebAuthn demo listening on http://${info.address}:${String(info.port)}`);
    if (bootstrap) {
      console.log('');
      console.log('Initial administrator enrollment URL:');
      console.log(bootstrap.enrollmentUrl);
      console.log(`Expires: ${new Date(bootstrap.expiresAt).toISOString()}`);
    } else {
      console.log('The bootstrap administrator already has a passkey.');
    }
  },
);

/**
 * Reap the rows nothing else removes.
 *
 * `cleanup()` is documented as something a host schedules, and until now no example
 * scheduled it — so a long-running deployment accumulated expired grants,
 * challenges, sessions and DPoP records for the life of the database. The demo's own
 * `demo_signups` was never reaped by anything either, and each row holds an email
 * address, a phone number and two OTP hashes.
 *
 * Every few minutes is ample. Nothing here is urgent: expiry is enforced in the
 * queries themselves, so an unreaped row is already unusable and this only reclaims
 * space and stops holding personal data indefinitely.
 */
const CLEANUP_INTERVAL_MS = 5 * 60_000;

async function reapExpiredRows(): Promise<void> {
  try {
    const reaped = await authentication.cleanup();
    const signups = reapSignups(database, Date.now());
    const total =
      reaped.enrollmentGrants +
      reaped.challenges +
      reaped.sessions +
      reaped.dpopProofs +
      reaped.dpopNonces +
      signups;
    if (total > 0) {
      console.log(
        `cleanup: ${String(reaped.enrollmentGrants)} grants, ` +
          `${String(reaped.challenges)} challenges, ${String(reaped.sessions)} sessions, ` +
          `${String(reaped.dpopProofs + reaped.dpopNonces)} DPoP rows, ` +
          `${String(signups)} signups`,
      );
    }
  } catch (error) {
    // A failed sweep must not stop the server; the next one will retry.
    console.error('cleanup failed:', error);
  }
}

// One pass at startup clears whatever expired while the process was down.
void reapExpiredRows();
// `unref` so the timer never holds the process open on its own.
const cleanupTimer = setInterval(() => void reapExpiredRows(), CLEANUP_INTERVAL_MS);
cleanupTimer.unref();

function shutdown(signal: string): void {
  console.log(`Received ${signal}; stopping demo`);
  clearInterval(cleanupTimer);
  server.close(() => {
    database.close();
    process.exit(0);
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
