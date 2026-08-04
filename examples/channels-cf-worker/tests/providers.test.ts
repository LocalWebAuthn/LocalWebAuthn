import { describe, expect, it, vi } from 'vitest';

import type { ChannelsEnv } from '../src/env.js';
import { sendEmail } from '../src/resend.js';
import { sendSms } from '../src/twilio.js';

const env: ChannelsEnv = {
  TWILIO_ACCOUNT_SID: 'ACtest',
  TWILIO_AUTH_TOKEN: 'token',
  TWILIO_PHONE_NUMBER: '+15550001111',
  RESEND_API_KEY: 're_test',
  RESEND_FROM: 'enroll@example.test',
};

function fetchInputUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') {
    return input;
  }
  if (input instanceof URL) {
    return input.href;
  }
  return input.url;
}

describe('sendSms', () => {
  it('posts form-encoded credentials to the Twilio Messages API', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValue(
        new Response(JSON.stringify({ sid: 'SMxxx', status: 'queued' }), { status: 201 }),
      );

    const result = await sendSms(
      env,
      { to: '+15551234567', body: 'Your code is 123456' },
      fetchImpl,
    );

    expect(result.ok).toBe(true);
    expect(result.status).toBe(201);
    expect(fetchImpl).toHaveBeenCalledOnce();
    const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://api.twilio.com/2010-04-01/Accounts/ACtest/Messages.json');
    expect(init.method).toBe('POST');
    expect(init.headers).toMatchObject({
      Authorization: `Basic ${btoa('ACtest:token')}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    });
    const body = init.body as URLSearchParams;
    expect(body.get('To')).toBe('+15551234567');
    expect(body.get('From')).toBe('+15550001111');
    expect(body.get('Body')).toBe('Your code is 123456');
  });

  it('honours TWILIO_API_BASE for local mocks', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response('{}', { status: 200 }));
    await sendSms(
      { ...env, TWILIO_API_BASE: 'http://127.0.0.1:9999' },
      { to: '+1', body: 'x' },
      fetchImpl,
    );
    const twilioCall = fetchImpl.mock.calls[0];
    expect(twilioCall).toBeDefined();
    expect(fetchInputUrl(twilioCall[0])).toContain(
      'http://127.0.0.1:9999/2010-04-01/Accounts/ACtest/Messages.json',
    );
  });

  it('fails closed when bindings are missing', async () => {
    await expect(
      sendSms({ ...env, TWILIO_AUTH_TOKEN: '' }, { to: '+1', body: 'x' }),
    ).rejects.toThrow(/TWILIO_AUTH_TOKEN/u);
  });
});

describe('sendEmail', () => {
  it('posts JSON to Resend with Bearer auth', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(JSON.stringify({ id: 'email_123' }), { status: 200 }));

    const result = await sendEmail(
      env,
      {
        to: 'user@example.test',
        subject: 'Enrollment',
        html: '<p>Open your enrollment link</p>',
        text: 'Open your enrollment link',
      },
      fetchImpl,
    );

    expect(result.ok).toBe(true);
    const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://api.resend.com/emails');
    expect(init.headers).toMatchObject({
      Authorization: 'Bearer re_test',
      'Content-Type': 'application/json',
    });
    expect(JSON.parse(init.body as string)).toEqual({
      from: 'enroll@example.test',
      to: ['user@example.test'],
      subject: 'Enrollment',
      html: '<p>Open your enrollment link</p>',
      text: 'Open your enrollment link',
    });
  });

  it('honours RESEND_API_BASE for local mocks', async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response('{}', { status: 200 }));
    await sendEmail(
      { ...env, RESEND_API_BASE: 'http://mock.local' },
      { to: 'a@b.c', subject: 's', html: '<p>x</p>' },
      fetchImpl,
    );
    const resendCall = fetchImpl.mock.calls[0];
    expect(resendCall).toBeDefined();
    expect(fetchInputUrl(resendCall[0])).toBe('http://mock.local/emails');
  });
});
