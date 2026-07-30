import { serve } from '@hono/node-server';

import { createDemoApplication, ensureBootstrapAdministrator } from './application';
import { openDemoDatabase } from './database';

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

function shutdown(signal: string): void {
  console.log(`Received ${signal}; stopping demo`);
  server.close(() => {
    database.close();
    process.exit(0);
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
