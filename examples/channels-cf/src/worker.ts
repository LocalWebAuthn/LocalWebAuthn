/**
 * Fully-Cloudflare delivery example: Workers + D1, Resend + Twilio.
 *
 * Delivery is internal — the send functions are imports, not routes. The only
 * public surface is the app's own flow (`POST /api/invite`), which is guarded
 * by a bearer token standing in for your real session or admin authorization,
 * sends only the fixed templates, and never returns the enrollment link.
 */

import type { Destination, EnrollmentDelivery } from '@localwebauthn/channels-core';
import type { D1DatabaseLike } from '@localwebauthn/server/d1';

import {
  enrollmentEmail,
  enrollmentSms,
  inviteAndDeliver,
  otpEmail,
  otpSms,
  parseAllowedPrefixes,
  sendEmailResend,
  sendSms,
  type ResendConfig,
  type TwilioConfig,
} from '@localwebauthn/channels-core';
import { createUserHandle, LocalWebAuthn, sha256 } from '@localwebauthn/server';
import { D1LocalWebAuthnStore, migrateD1 } from '@localwebauthn/server/d1';

export type WorkerEnv = {
  /** D1 binding holding both the app `users` table and the LocalWebAuthn tables. */
  AUTH: D1DatabaseLike;
  /** Stand-in for your real route authorization; the route refuses without it. */
  INVITE_API_TOKEN: string;
  /** Exact public origin of the app, e.g. `https://app.example.com`. */
  PUBLIC_ORIGIN: string;
  APP_NAME: string;
  RESEND_API_KEY: string;
  RESEND_FROM: string;
  TWILIO_ACCOUNT_SID: string;
  TWILIO_AUTH_TOKEN: string;
  TWILIO_PHONE_NUMBER: string;
  /** Comma-separated country prefixes, e.g. `+1,+44`. Strongly recommended. */
  SMS_ALLOWED_PREFIXES?: string;
  /** Test overrides. */
  TWILIO_API_BASE?: string;
  RESEND_API_BASE?: string;
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

/** Compare secrets by their digests so length and content leak nothing. */
async function secretsEqual(presented: string, expected: string): Promise<boolean> {
  const [a, b] = await Promise.all([sha256(presented), sha256(expected)]);
  let difference = 0;
  for (const [index, byte] of a.entries()) {
    difference |= byte ^ b[index];
  }
  return difference === 0;
}

function bearerToken(request: Request): string {
  const header = request.headers.get('Authorization') ?? '';
  return header.startsWith('Bearer ') ? header.slice('Bearer '.length) : '';
}

/** D1 returns BLOB columns as ArrayBuffer or number[] depending on the path. */
function toHandle(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  return Uint8Array.from(value as number[]);
}

async function ensureSchema(env: WorkerEnv): Promise<void> {
  await migrateD1(env.AUTH);
  await env.AUTH.prepare(
    `CREATE TABLE IF NOT EXISTS users (
         id TEXT PRIMARY KEY,
         email TEXT NOT NULL UNIQUE,
         display_name TEXT NOT NULL,
         active INTEGER NOT NULL DEFAULT 1,
         webauthn_user_handle BLOB NOT NULL UNIQUE,
         created_at INTEGER NOT NULL
       )`,
  ).run();
}

function createAuth(env: WorkerEnv): LocalWebAuthn {
  const origin = new URL(env.PUBLIC_ORIGIN);
  return new LocalWebAuthn({
    rpName: env.APP_NAME,
    rpId: origin.hostname,
    expectedOrigins: origin.origin,
    publicOrigin: origin.origin,
    store: new D1LocalWebAuthnStore(env.AUTH),
    users: {
      getUser: async (userId) => {
        const row = await env.AUTH.prepare(
          `SELECT id, email, display_name, active, webauthn_user_handle FROM users WHERE id = ?`,
        )
          .bind(userId)
          .first<{
            id: string;
            email: string;
            display_name: string;
            active: number;
            webauthn_user_handle: unknown;
          }>();
        return row
          ? {
              id: row.id,
              name: row.email,
              displayName: row.display_name,
              active: row.active === 1,
              webAuthnUserHandle: toHandle(row.webauthn_user_handle),
            }
          : null;
      },
    },
  });
}

/** Resend + Twilio, wrapping the fixed templates — the Workers counterpart of channels-node. */
function createDelivery(env: WorkerEnv): EnrollmentDelivery {
  const appName = env.APP_NAME;
  const resend: ResendConfig = {
    apiKey: env.RESEND_API_KEY,
    from: env.RESEND_FROM,
    apiBase: env.RESEND_API_BASE,
  };
  const twilio: TwilioConfig = {
    accountSid: env.TWILIO_ACCOUNT_SID,
    authToken: env.TWILIO_AUTH_TOKEN,
    from: env.TWILIO_PHONE_NUMBER,
    allowedPrefixes: parseAllowedPrefixes(env.SMS_ALLOWED_PREFIXES),
    apiBase: env.TWILIO_API_BASE,
  };

  async function sendBoth(
    to: Destination,
    email: () => ReturnType<typeof enrollmentEmail>,
    sms: () => string,
  ) {
    const results = [];
    if (to.email) {
      results.push(await sendEmailResend(resend, to.email, email()));
    }
    if (to.phone) {
      results.push(await sendSms(twilio, { to: to.phone, body: sms() }));
    }
    return results;
  }

  return {
    enrollment: (to, params) =>
      sendBoth(
        to,
        () => enrollmentEmail({ appName, ...params }),
        () => enrollmentSms({ appName, ...params }),
      ),
    otp: (to, params) =>
      sendBoth(
        to,
        () => otpEmail({ appName, ...params }),
        () => otpSms({ appName, ...params }),
      ),
  };
}

async function findOrCreateUser(
  env: WorkerEnv,
  input: { email: string; displayName: string },
): Promise<string> {
  const existing = await env.AUTH.prepare(`SELECT id FROM users WHERE email = ?`)
    .bind(input.email)
    .first<{ id: string }>();
  if (existing) {
    return existing.id;
  }
  const id = crypto.randomUUID();
  await env.AUTH.prepare(
    `INSERT INTO users(id, email, display_name, webauthn_user_handle, created_at)
       VALUES (?, ?, ?, ?, ?)`,
  )
    .bind(id, input.email, input.displayName, createUserHandle(), Date.now())
    .run();
  return id;
}

const worker = {
  async fetch(request: Request, env: WorkerEnv): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/health') {
      return json({ status: 'ok', service: 'localwebauthn-channels-cf' });
    }

    if (request.method === 'POST' && url.pathname === '/api/invite') {
      // Fail closed: no configured token means no invites, not open invites.
      if (
        !env.INVITE_API_TOKEN ||
        !(await secretsEqual(bearerToken(request), env.INVITE_API_TOKEN))
      ) {
        return json({ error: 'unauthorized', message: 'A valid bearer token is required.' }, 401);
      }

      const body = (await request.json().catch(() => ({}))) as {
        email?: string;
        phone?: string;
        displayName?: string;
      };
      const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
      const displayName = typeof body.displayName === 'string' ? body.displayName.trim() : '';
      const phone = typeof body.phone === 'string' ? body.phone.trim() : undefined;
      if (!email || !displayName) {
        return json(
          { error: 'invalid_invite', message: 'email and displayName are required.' },
          400,
        );
      }

      await ensureSchema(env);
      const userId = await findOrCreateUser(env, { email, displayName });
      const outcome = await inviteAndDeliver(createAuth(env), createDelivery(env), {
        userId,
        to: { email, phone },
      });
      // No enrollment URL or token in the response — the only copy went to
      // the destination channels.
      return json({ delivered: outcome.delivered, expiresAt: outcome.expiresAt });
    }

    return json({ error: 'not_found', message: 'This worker has no send API.' }, 404);
  },
};

export default worker;
