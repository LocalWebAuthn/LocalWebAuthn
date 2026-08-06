import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { fileURLToPath } from 'node:url';

import { build } from 'esbuild';
import { Miniflare } from 'miniflare';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/** Bundle the real worker entry point so Miniflare runs the shipped source. */
async function bundledWorkerScript(): Promise<string> {
  const result = await build({
    entryPoints: [fileURLToPath(new URL('../src/worker.ts', import.meta.url))],
    bundle: true,
    format: 'esm',
    write: false,
    target: 'es2022',
  });
  return result.outputFiles[0].text;
}

describe('channels-cf worker (Miniflare, real bundled source)', () => {
  let miniflare: Miniflare;
  let mockServer: ReturnType<typeof createServer>;
  const providerRequests: { url?: string; body: string }[] = [];

  beforeAll(async () => {
    mockServer = createServer((request: IncomingMessage, response: ServerResponse) => {
      const chunks: Uint8Array[] = [];
      request.on('data', (chunk: string | Buffer) => {
        chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : new Uint8Array(chunk));
      });
      request.on('end', () => {
        providerRequests.push({ url: request.url, body: Buffer.concat(chunks).toString('utf8') });
        response.writeHead(201, { 'Content-Type': 'application/json' });
        response.end(JSON.stringify({ sid: 'SM-mock', id: 'email-mock' }));
      });
    });
    await new Promise<void>((resolve) => {
      mockServer.listen(0, '127.0.0.1', () => resolve());
    });
    const address = mockServer.address();
    if (!address || typeof address === 'string') {
      throw new Error('mock server failed to bind');
    }
    const mockOrigin = `http://127.0.0.1:${String(address.port)}`;

    miniflare = new Miniflare({
      compatibilityDate: '2026-07-29',
      modules: true,
      script: await bundledWorkerScript(),
      d1Databases: ['AUTH'],
      bindings: {
        INVITE_API_TOKEN: 'test-invite-token',
        PUBLIC_ORIGIN: 'https://app.example.test',
        APP_NAME: 'Example',
        RESEND_API_KEY: 're_test',
        RESEND_FROM: 'enroll@example.test',
        TWILIO_ACCOUNT_SID: 'ACtest',
        TWILIO_AUTH_TOKEN: 'twilio-token',
        TWILIO_PHONE_NUMBER: '+15550001111',
        SMS_ALLOWED_PREFIXES: '+1',
        TWILIO_API_BASE: mockOrigin,
        RESEND_API_BASE: mockOrigin,
      },
    });
  });

  afterAll(async () => {
    await miniflare.dispose();
    await new Promise<void>((resolve, reject) => {
      mockServer.close((error) => (error ? reject(error) : resolve()));
    });
  });

  function invite(body: unknown, token = 'test-invite-token') {
    return miniflare.dispatchFetch('http://localhost/api/invite', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    });
  }

  it('has no send API at all', async () => {
    const health = await miniflare.dispatchFetch('http://localhost/health');
    expect(health.status).toBe(200);
    for (const path of ['/send-email', '/send-sms']) {
      const response = await miniflare.dispatchFetch(`http://localhost${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to: 'a@b.c', subject: 'x', html: 'y' }),
      });
      expect(response.status).toBe(404);
    }
  });

  it('refuses invites without the bearer token, failing closed', async () => {
    const missing = await miniflare.dispatchFetch('http://localhost/api/invite', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'a@example.test', displayName: 'A' }),
    });
    expect(missing.status).toBe(401);
    const wrong = await invite({ email: 'a@example.test', displayName: 'A' }, 'wrong-token');
    expect(wrong.status).toBe(401);
    expect(providerRequests).toHaveLength(0);
  });

  it('issues a grant on D1 and delivers it internally, leaking no token to the caller', async () => {
    providerRequests.length = 0;
    const response = await invite({
      email: 'ada@example.test',
      phone: '+15551234567',
      displayName: 'Ada Example',
    });
    expect(response.status).toBe(200);
    const payload = (await response.json()) as { delivered: boolean; expiresAt: number };
    expect(payload.delivered).toBe(true);
    expect(payload.expiresAt).toBeGreaterThan(Date.now());
    expect(JSON.stringify(payload)).not.toContain('token=');

    // The one-time link reached both providers, inside the fixed templates.
    const email = providerRequests.find((entry) => entry.url === '/emails');
    const sms = providerRequests.find((entry) => entry.url?.includes('Messages.json'));
    expect(email?.body).toContain('https://app.example.test/enroll#token=');
    expect(decodeURIComponent(sms?.body ?? '')).toContain('https://app.example.test/enroll#token=');

    // Re-inviting the same person supersedes the grant and delivers again.
    const again = await invite({ email: 'ada@example.test', displayName: 'Ada Example' });
    expect(again.status).toBe(200);
    await expect(again.json()).resolves.toMatchObject({ delivered: true });
  });
});
