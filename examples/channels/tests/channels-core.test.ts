import { describe, expect, it, vi } from 'vitest';

import {
  assertE164,
  assertEmailAddress,
  enrollmentEmail,
  enrollmentSms,
  inviteAndDeliver,
  otpSms,
  parseAllowedPrefixes,
  sendEmailResend,
  sendSms,
  type DeliveryResult,
} from '../src/index.js';

const url =
  'https://app.example.com/enroll#token=abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst';

describe('templates', () => {
  it('renders fixed enrollment copy with the URL escaped into it', () => {
    const email = enrollmentEmail({ appName: 'Example <App>', url, expiresAt: 1_000 });
    expect(email.subject).toBe('Create your Example <App> passkey');
    expect(email.text).toContain(url);
    expect(email.html).toContain('Example &lt;App&gt;');
    expect(email.html).toContain(`href="${url}"`);
    expect(enrollmentSms({ appName: 'Example', url })).toContain(url);
    expect(otpSms({ appName: 'Example', code: '123456' })).toContain('123456');
  });
});

describe('destination validation', () => {
  it('accepts E.164 within allowed prefixes and rejects everything else', () => {
    expect(assertE164('+15551234567')).toBe('+15551234567');
    expect(assertE164(' +15551234567 ', ['+1'])).toBe('+15551234567');
    expect(() => assertE164('5551234567')).toThrow(TypeError);
    expect(() => assertE164('+15551234567', ['+44'])).toThrow(/SMS_ALLOWED_PREFIXES/u);
    expect(assertEmailAddress(' Person@Example.COM ')).toBe('person@example.com');
    expect(() => assertEmailAddress('not-an-email')).toThrow(TypeError);
    expect(parseAllowedPrefixes('+1, +44')).toEqual(['+1', '+44']);
    expect(parseAllowedPrefixes('')).toBeUndefined();
  });
});

describe('providers', () => {
  it('posts form-encoded Twilio sends and normalizes the result', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(JSON.stringify({ sid: 'SM1' }), { status: 201 }));
    const result = await sendSms(
      { accountSid: 'ACtest', authToken: 'token', from: '+15550001111', allowedPrefixes: ['+1'] },
      { to: '+15551234567', body: 'Example verification code: 123456. Never share it.' },
      fetchImpl,
    );
    expect(result).toEqual({ ok: true, provider: 'twilio', id: 'SM1' });
    const [endpoint, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(endpoint).toBe('https://api.twilio.com/2010-04-01/Accounts/ACtest/Messages.json');
    expect(init.headers).toMatchObject({
      Authorization: `Basic ${btoa('ACtest:token')}`,
    });
    const body = init.body as URLSearchParams;
    expect(body.get('To')).toBe('+15551234567');
    expect(body.get('From')).toBe('+15550001111');
  });

  it('sends Resend email with bearer auth and hides provider bodies on failure', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 'email_1' }), { status: 200 }))
      .mockResolvedValueOnce(new Response('secret provider detail', { status: 401 }));
    const content = enrollmentEmail({ appName: 'Example', url });
    const ok = await sendEmailResend(
      { apiKey: 're_test', from: 'enroll@example.test' },
      'person@example.test',
      content,
      fetchImpl,
    );
    expect(ok).toEqual({ ok: true, provider: 'resend', id: 'email_1' });
    const bad = await sendEmailResend(
      { apiKey: 're_test', from: 'enroll@example.test' },
      'person@example.test',
      content,
      fetchImpl,
    );
    expect(bad).toEqual({ ok: false, provider: 'resend', error: 'HTTP 401' });
    expect(JSON.stringify(bad)).not.toContain('secret provider detail');
  });
});

describe('inviteAndDeliver', () => {
  it('issues a grant, delivers on the bound channels, and never returns the link', async () => {
    const sent: { to: string; body: string }[] = [];
    const auth = {
      issueEnrollment: vi.fn(async () => ({
        grantId: 'grant-new',
        enrollmentUrl: url,
        expiresAt: 99_000,
        supersededGrantIds: ['old-grant'],
      })),
      revokePendingEnrollments: vi.fn(async () => [] as string[]),
    };
    const delivery = {
      enrollment: async (
        to: { email?: string; phone?: string },
        params: { url: string },
      ): Promise<DeliveryResult[]> => {
        sent.push({ to: to.email ?? to.phone ?? '', body: params.url });
        return [{ ok: true, provider: 'smtp' as const }];
      },
      otp: async (): Promise<DeliveryResult[]> => [],
    };

    const outcome = await inviteAndDeliver(auth, delivery, {
      userId: 'user-1',
      to: { email: 'person@example.test' },
    });
    expect(outcome).toMatchObject({
      delivered: true,
      anyDelivered: true,
      grantStatus: 'live',
      grantId: 'grant-new',
      expiresAt: 99_000,
      supersededGrantIds: ['old-grant'],
      revokedGrantIds: [],
    });
    expect(JSON.stringify(outcome)).not.toContain('token=');
    expect(sent[0].body).toBe(url);
    expect(auth.revokePendingEnrollments).not.toHaveBeenCalled();

    await expect(inviteAndDeliver(auth, delivery, { userId: 'user-1', to: {} })).rejects.toThrow(
      TypeError,
    );
  });

  it('revokes the pending grant when every channel rejects delivery', async () => {
    const auth = {
      issueEnrollment: vi.fn(async () => ({
        grantId: 'grant-dead',
        enrollmentUrl: url,
        expiresAt: 99_000,
        supersededGrantIds: [] as string[],
      })),
      revokePendingEnrollments: vi.fn(async () => ['grant-dead']),
    };
    const delivery = {
      enrollment: async (): Promise<DeliveryResult[]> => [
        { ok: false, provider: 'smtp' as const, error: 'HTTP 550' },
        { ok: false, provider: 'twilio' as const, error: 'HTTP 400' },
      ],
      otp: async (): Promise<DeliveryResult[]> => [],
    };

    const outcome = await inviteAndDeliver(auth, delivery, {
      userId: 'user-1',
      to: { email: 'person@example.test', phone: '+15551234567' },
    });
    expect(outcome).toMatchObject({
      delivered: false,
      anyDelivered: false,
      grantStatus: 'revoked_after_delivery_failure',
      revokedGrantIds: ['grant-dead'],
    });
    expect(auth.revokePendingEnrollments).toHaveBeenCalledWith('user-1');
  });

  it('keeps the grant live when at least one channel accepts (partial delivery)', async () => {
    const auth = {
      issueEnrollment: vi.fn(async () => ({
        grantId: 'grant-partial',
        enrollmentUrl: url,
        expiresAt: 99_000,
        supersededGrantIds: [] as string[],
      })),
      revokePendingEnrollments: vi.fn(async () => [] as string[]),
    };
    const delivery = {
      enrollment: async (): Promise<DeliveryResult[]> => [
        { ok: true, provider: 'smtp' as const, id: 'msg-1' },
        { ok: false, provider: 'twilio' as const, error: 'HTTP 400' },
      ],
      otp: async (): Promise<DeliveryResult[]> => [],
    };

    const outcome = await inviteAndDeliver(auth, delivery, {
      userId: 'user-1',
      to: { email: 'person@example.test', phone: '+15551234567' },
    });
    expect(outcome.grantStatus).toBe('live');
    expect(outcome.delivered).toBe(false);
    expect(outcome.anyDelivered).toBe(true);
    expect(auth.revokePendingEnrollments).not.toHaveBeenCalled();
  });

  it('revokes the grant when delivery throws before any result', async () => {
    const auth = {
      issueEnrollment: vi.fn(async () => ({
        grantId: 'grant-throw',
        enrollmentUrl: url,
        expiresAt: 99_000,
        supersededGrantIds: [] as string[],
      })),
      revokePendingEnrollments: vi.fn(async () => ['grant-throw']),
    };
    const delivery = {
      enrollment: async (): Promise<DeliveryResult[]> => {
        throw new Error('network down');
      },
      otp: async (): Promise<DeliveryResult[]> => [],
    };

    const outcome = await inviteAndDeliver(auth, delivery, {
      userId: 'user-1',
      to: { email: 'person@example.test' },
    });
    expect(outcome.grantStatus).toBe('revoked_after_delivery_failure');
    expect(outcome.results[0]?.error).toBe('network down');
    expect(auth.revokePendingEnrollments).toHaveBeenCalledWith('user-1');
  });
});
