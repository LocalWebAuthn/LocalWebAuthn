import type { ChannelsEnv, FetchLike } from './env.js';
import { requireBinding } from './env.js';

export type SendSmsInput = {
  to: string;
  body: string;
};

export type SendSmsResult = {
  ok: boolean;
  status: number;
  body: string;
};

/**
 * Send an SMS via Twilio's Messages API.
 *
 * @see https://www.twilio.com/docs/sms/api/message-resource#create-a-message-resource
 */
export async function sendSms(
  env: ChannelsEnv,
  input: SendSmsInput,
  fetchImpl: FetchLike = fetch,
): Promise<SendSmsResult> {
  const accountSid = requireBinding(env, 'TWILIO_ACCOUNT_SID');
  const authToken = requireBinding(env, 'TWILIO_AUTH_TOKEN');
  const from = requireBinding(env, 'TWILIO_PHONE_NUMBER');
  const base = (env.TWILIO_API_BASE ?? 'https://api.twilio.com').replace(/\/+$/u, '');
  const endpoint = `${base}/2010-04-01/Accounts/${accountSid}/Messages.json`;

  const payload = new URLSearchParams({
    To: input.to,
    From: from,
    Body: input.body,
  });

  const credentials = btoa(`${accountSid}:${authToken}`);
  const response = await fetchImpl(endpoint, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: payload,
  });

  return {
    ok: response.ok,
    status: response.status,
    body: await response.text(),
  };
}
