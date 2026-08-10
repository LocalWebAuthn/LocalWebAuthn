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
  passkeyCreatedEmail,
  passkeyCreatedSms,
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

  /**
   * The passkey-created notice is the only push signal in the system: every other
   * one reaches the person only if they come back and hit a failure. So it has to
   * carry a remedy, not just an alert — and in order, because re-enrolling into a
   * mailbox that is still compromised simply repeats the problem.
   */
  it('renders a passkey-created notice carrying the remedy in order', () => {
    const params = {
      appName: 'Example <App>',
      label: 'Work laptop',
      supportContact: 'security@example.com',
    };
    const email = passkeyCreatedEmail(params);
    expect(email.subject).toBe('A passkey was created for your Example <App> account');
    expect(email.text).toContain('Work laptop');
    expect(email.html).toContain('Example &lt;App&gt;');

    // Lock the account, then re-secure the channels, then re-enroll.
    const lock = email.text.indexOf('lock the account');
    const resecure = email.text.indexOf('Re-secure your email and phone');
    const reenroll = email.text.indexOf('new enrollment invitation');
    expect(lock).toBeGreaterThan(-1);
    expect(lock).toBeLessThan(resecure);
    expect(resecure).toBeLessThan(reenroll);

    // It has to state the benign reading too, or a routine enrollment reads as an
    // incident every time.
    expect(email.text).toContain('If that was you');

    const sms = passkeyCreatedSms(params);
    expect(sms).toContain('Work laptop');
    expect(sms).toContain('security@example.com');
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
        enrollmentUrl: url,
        expiresAt: 99_000,
        supersededGrantIds: ['old-grant'],
      })),
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
      expiresAt: 99_000,
      supersededGrantIds: ['old-grant'],
    });
    expect(JSON.stringify(outcome)).not.toContain('token=');
    expect(sent[0].body).toBe(url);

    await expect(inviteAndDeliver(auth, delivery, { userId: 'user-1', to: {} })).rejects.toThrow(
      TypeError,
    );
  });
});
