import type { AuthUser } from '@localwebauthn/server';

import { createUserHandle, LocalWebAuthn } from '@localwebauthn/server';
import { migrateSqlite, SqliteLocalWebAuthnStore } from '@localwebauthn/server/sqlite';
import Database from 'better-sqlite3';
import { createTransport } from 'nodemailer';
import { describe, expect, it, vi } from 'vitest';

import { createDelivery, inviteAndDeliver } from '../src/index.js';

const environment = {
  APP_NAME: 'Example',
  SMTP_URL: 'smtps://user%40example.test:app-password@smtp.example.test:465',
  SMTP_FROM: '"Example" <enroll@example.test>',
  TWILIO_ACCOUNT_SID: 'ACtest',
  TWILIO_AUTH_TOKEN: 'token',
  TWILIO_PHONE_NUMBER: '+15550001111',
  SMS_ALLOWED_PREFIXES: '+1',
};

/** Buffers messages instead of opening SMTP connections. */
function bufferTransport() {
  return createTransport({ streamTransport: true, buffer: true, newline: 'unix' });
}

describe('channels-node delivery', () => {
  it('reports configured channels and refuses unconfigured ones loudly', async () => {
    const nothing = createDelivery({});
    expect(nothing.channels).toEqual({ email: false, sms: false });
    await expect(
      nothing.enrollment({ email: 'a@example.test' }, { url: 'https://x.example/enroll#token=t' }),
    ).rejects.toThrow(/SMTP_URL/u);

    const smsOnly = createDelivery(
      { ...environment, SMTP_URL: undefined, SMTP_FROM: undefined },
      { fetchImpl: vi.fn() },
    );
    expect(smsOnly.channels).toEqual({ email: false, sms: true });
  });

  it('delivers a real enrollment grant over SMTP and Twilio, leaking no token to the caller', async () => {
    const database = new Database(':memory:');
    database.pragma('foreign_keys = ON');
    migrateSqlite(database);
    const user: AuthUser = {
      id: 'user-1',
      name: 'person@example.test',
      displayName: 'Person Example',
      active: true,
      webAuthnUserHandle: createUserHandle(),
    };
    const auth = new LocalWebAuthn({
      rpName: 'Example',
      rpId: 'app.example.test',
      expectedOrigins: 'https://app.example.test',
      publicOrigin: 'https://app.example.test',
      store: new SqliteLocalWebAuthnStore(database),
      users: { getUser: async (id) => (id === user.id ? user : null) },
    });

    const smsCalls: string[] = [];
    const fetchImpl = vi.fn<typeof fetch>(async (input, init) => {
      smsCalls.push(String((init?.body as URLSearchParams).get('Body')));
      void input;
      return new Response(JSON.stringify({ sid: 'SM1' }), { status: 201 });
    });
    const transporter = bufferTransport();
    const sentMail: string[] = [];
    const originalSendMail = transporter.sendMail.bind(transporter);
    transporter.sendMail = async (options: Parameters<typeof originalSendMail>[0]) => {
      const info = await originalSendMail(options);
      sentMail.push((info as { message: Buffer }).message.toString('utf8'));
      return info;
    };

    const delivery = createDelivery(environment, { transporter, fetchImpl });
    expect(delivery.channels).toEqual({ email: true, sms: true });

    const outcome = await inviteAndDeliver(auth, delivery, {
      userId: user.id,
      to: { email: 'person@example.test', phone: '+15551234567' },
    });

    expect(outcome.delivered).toBe(true);
    expect(outcome.results.map((result) => result.provider)).toEqual(['smtp', 'twilio']);
    // The one-time link reached both channels...
    expect(sentMail[0]).toContain('/enroll#token=');
    expect(smsCalls[0]).toContain('/enroll#token=');
    // ...and is not present in what the caller gets back.
    expect(JSON.stringify(outcome)).not.toContain('token=');
    database.close();
  });

  it('rejects SMS destinations outside the allowed prefixes before any send', async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const delivery = createDelivery(environment, {
      transporter: bufferTransport(),
      fetchImpl,
    });
    await expect(delivery.otp({ phone: '+447700900000' }, { code: '123456' })).rejects.toThrow(
      /SMS_ALLOWED_PREFIXES/u,
    );
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
