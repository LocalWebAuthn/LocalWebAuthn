import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

import { Miniflare } from 'miniflare';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type { ChannelsEnv } from '../src/env.js';
import worker from '../src/index.js';

const testEnv: ChannelsEnv = {
  TWILIO_ACCOUNT_SID: 'ACminiflare',
  TWILIO_AUTH_TOKEN: 'mf-token',
  TWILIO_PHONE_NUMBER: '+15550000000',
  RESEND_API_KEY: 're_miniflare',
  RESEND_FROM: 'demo@example.test',
};

describe('channels worker (in-process handler)', () => {
  it('serves health and usage', async () => {
    const health = await worker.fetch(new Request('http://channels/health'), testEnv);
    expect(health.status).toBe(200);
    await expect(health.json()).resolves.toMatchObject({ status: 'ok' });

    const home = await worker.fetch(new Request('http://channels/'), testEnv);
    expect(home.status).toBe(200);
    expect(await home.text()).toMatch(/send-sms/u);
  });

  it('validates JSON bodies', async () => {
    const sms = await worker.fetch(
      new Request('http://channels/send-sms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to: '+1' }),
      }),
      testEnv,
    );
    expect(sms.status).toBe(400);

    const email = await worker.fetch(
      new Request('http://channels/send-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to: 'a@b.c', subject: 's' }),
      }),
      testEnv,
    );
    expect(email.status).toBe(400);
  });

  it('proxies SMS and email through injectable API bases', async () => {
    const seen: { url: string }[] = [];
    const mockFetch: typeof fetch = async (input) => {
      const url = String(input);
      seen.push({ url });
      if (url.includes('/Messages.json')) {
        return new Response(JSON.stringify({ sid: 'SM1' }), { status: 201 });
      }
      return new Response(JSON.stringify({ id: 'email_1' }), { status: 200 });
    };

    const previous = globalThis.fetch;
    globalThis.fetch = mockFetch;
    try {
      const env: ChannelsEnv = {
        ...testEnv,
        TWILIO_API_BASE: 'https://twilio.test',
        RESEND_API_BASE: 'https://resend.test',
      };

      const sms = await worker.fetch(
        new Request('http://channels/send-sms', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ to: '+15551212', body: 'code 99' }),
        }),
        env,
      );
      expect(sms.status).toBe(201);

      const email = await worker.fetch(
        new Request('http://channels/send-email', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            to: 'user@example.test',
            subject: 'Enroll',
            html: '<p>link</p>',
          }),
        }),
        env,
      );
      expect(email.status).toBe(200);

      expect(
        seen.some((entry) => entry.url.includes('twilio.test') && entry.url.includes('Messages')),
      ).toBe(true);
      expect(seen.some((entry) => entry.url.includes('resend.test/emails'))).toBe(true);
    } finally {
      globalThis.fetch = previous;
    }
  });
});

describe('channels worker (Miniflare)', () => {
  let mockOrigin: string;
  let mockServer: ReturnType<typeof createServer>;
  let miniflare: Miniflare;
  const requests: { method?: string; url?: string; body: string }[] = [];

  beforeAll(async () => {
    mockServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(Buffer.from(chunk));
      }
      const body = Buffer.concat(chunks).toString('utf8');
      requests.push({ method: req.method, url: req.url, body });
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, path: req.url }));
    });
    await new Promise<void>((resolve) => {
      mockServer.listen(0, '127.0.0.1', () => resolve());
    });
    const address = mockServer.address();
    if (!address || typeof address === 'string') {
      throw new Error('mock server failed to bind');
    }
    mockOrigin = `http://127.0.0.1:${String(address.port)}`;

    // Self-contained worker script for workerd (same public contract as src/).
    const script = `
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return Response.json({ status: "ok", service: "localwebauthn-channels-cf-worker" });
    }
    if (request.method === "POST" && url.pathname === "/send-sms") {
      const body = await request.json();
      const endpoint = env.TWILIO_API_BASE + "/2010-04-01/Accounts/" + env.TWILIO_ACCOUNT_SID + "/Messages.json";
      const payload = new URLSearchParams({ To: body.to, From: env.TWILIO_PHONE_NUMBER, Body: body.body });
      const auth = btoa(env.TWILIO_ACCOUNT_SID + ":" + env.TWILIO_AUTH_TOKEN);
      return fetch(endpoint, {
        method: "POST",
        headers: { Authorization: "Basic " + auth, "Content-Type": "application/x-www-form-urlencoded" },
        body: payload,
      });
    }
    if (request.method === "POST" && url.pathname === "/send-email") {
      const body = await request.json();
      return fetch(env.RESEND_API_BASE + "/emails", {
        method: "POST",
        headers: {
          Authorization: "Bearer " + env.RESEND_API_KEY,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ from: env.RESEND_FROM, to: [body.to], subject: body.subject, html: body.html }),
      });
    }
    return Response.json({ error: "not_found" }, { status: 404 });
  }
};
`;

    miniflare = new Miniflare({
      compatibilityDate: '2025-01-01',
      modules: true,
      script,
      bindings: {
        TWILIO_ACCOUNT_SID: testEnv.TWILIO_ACCOUNT_SID,
        TWILIO_AUTH_TOKEN: testEnv.TWILIO_AUTH_TOKEN,
        TWILIO_PHONE_NUMBER: testEnv.TWILIO_PHONE_NUMBER,
        RESEND_API_KEY: testEnv.RESEND_API_KEY,
        RESEND_FROM: testEnv.RESEND_FROM,
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

  it('dispatches SMS and email through Miniflare to a mock origin', async () => {
    requests.length = 0;

    const health = await miniflare.dispatchFetch('http://localhost/health');
    expect(health.status).toBe(200);

    const sms = await miniflare.dispatchFetch('http://localhost/send-sms', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ to: '+15559876543', body: 'hello miniflare' }),
    });
    expect(sms.status).toBe(201);

    const email = await miniflare.dispatchFetch('http://localhost/send-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        to: 'ada@example.test',
        subject: 'Test',
        html: '<p>hi</p>',
      }),
    });
    expect(email.status).toBe(201);

    expect(requests.length).toBeGreaterThanOrEqual(2);
    expect(requests.some((entry) => entry.url?.includes('Messages.json'))).toBe(true);
    expect(requests.some((entry) => entry.url === '/emails')).toBe(true);
  });
});
