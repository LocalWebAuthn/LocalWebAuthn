import type { ChannelsEnv } from './env.js';
import { sendEmail } from './resend.js';
import { sendSms } from './twilio.js';

export type { ChannelsEnv } from './env.js';
export { sendEmail } from './resend.js';
export { sendSms } from './twilio.js';

type JsonBody = Record<string, unknown>;

async function readJson(request: Request): Promise<JsonBody> {
  try {
    return (await request.json()) as JsonBody;
  } catch {
    return {};
  }
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

function text(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

/**
 * Minimal channel delivery worker for LocalWebAuthn host apps.
 *
 * Routes:
 * - `GET  /`          — usage
 * - `GET  /health`    — liveness
 * - `POST /send-sms`  — `{ "to": "+1…", "body": "…" }`
 * - `POST /send-email`— `{ "to": "a@b.c", "subject": "…", "html": "…" }`
 *
 * For LocalWebAuthn: use these only to deliver OTPs or enrollment links after
 * your app has bound the destination to the user. Do not accept an
 * attacker-supplied address as the recovery destination.
 */
const worker = {
  async fetch(request: Request, env: ChannelsEnv): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/health') {
      return json({ status: 'ok', service: 'localwebauthn-channels-cf-worker' });
    }

    if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '')) {
      return text(
        [
          'LocalWebAuthn channels worker (Twilio SMS + Resend email).',
          'POST /send-sms   JSON { to, body }',
          'POST /send-email JSON { to, subject, html }',
          'GET  /health',
        ].join('\n'),
      );
    }

    if (request.method === 'POST' && url.pathname === '/send-sms') {
      const body = await readJson(request);
      const to = typeof body.to === 'string' ? body.to.trim() : '';
      const message = typeof body.body === 'string' ? body.body : '';
      if (!to || !message) {
        return json(
          { error: 'invalid_request', message: 'JSON body requires string to and body.' },
          400,
        );
      }
      try {
        const result = await sendSms(env, { to, body: message });
        return new Response(result.body, {
          status: result.status,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'no-store',
          },
        });
      } catch (error) {
        const messageText = error instanceof Error ? error.message : 'SMS send failed.';
        return json({ error: 'sms_failed', message: messageText }, 500);
      }
    }

    if (request.method === 'POST' && url.pathname === '/send-email') {
      const body = await readJson(request);
      const to = typeof body.to === 'string' ? body.to.trim() : '';
      const subject = typeof body.subject === 'string' ? body.subject : '';
      const html = typeof body.html === 'string' ? body.html : '';
      if (!to || !subject || !html) {
        return json(
          { error: 'invalid_request', message: 'JSON body requires string to, subject, and html.' },
          400,
        );
      }
      try {
        const result = await sendEmail(env, {
          to,
          subject,
          html,
          text: typeof body.text === 'string' ? body.text : undefined,
        });
        return new Response(result.body, {
          status: result.status,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'no-store',
          },
        });
      } catch (error) {
        const messageText = error instanceof Error ? error.message : 'Email send failed.';
        return json({ error: 'email_failed', message: messageText }, 500);
      }
    }

    return json({ error: 'not_found', message: 'Use /send-sms or /send-email.' }, 404);
  },
};

export default worker;
