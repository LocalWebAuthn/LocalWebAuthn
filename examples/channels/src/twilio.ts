import type { DeliveryResult, FetchLike } from './types.js';

import { assertE164 } from './validate.js';

export type TwilioConfig = {
  accountSid: string;
  authToken: string;
  /** Sending number (E.164). */
  from: string;
  /** Restrict destinations to these country prefixes (recommended). */
  allowedPrefixes?: readonly string[];
  /** Override for tests / proxies. Default `https://api.twilio.com`. */
  apiBase?: string;
};

/**
 * Send an SMS via Twilio's Messages API. Works identically under Node and
 * Cloudflare Workers (fetch + FormData primitives only).
 *
 * The result is normalized — no raw provider bodies cross this boundary.
 *
 * @see https://www.twilio.com/docs/sms/api/message-resource#create-a-message-resource
 */
export async function sendSms(
  config: TwilioConfig,
  input: { to: string; body: string },
  fetchImpl: FetchLike = fetch,
): Promise<DeliveryResult> {
  const to = assertE164(input.to, config.allowedPrefixes);
  const base = (config.apiBase ?? 'https://api.twilio.com').replace(/\/+$/u, '');
  const endpoint = `${base}/2010-04-01/Accounts/${config.accountSid}/Messages.json`;

  const response = await fetchImpl(endpoint, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${btoa(`${config.accountSid}:${config.authToken}`)}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ To: to, From: config.from, Body: input.body }),
  });

  if (!response.ok) {
    return { ok: false, provider: 'twilio', error: `HTTP ${String(response.status)}` };
  }
  const body = (await response.json().catch(() => ({}))) as { sid?: string };
  return { ok: true, provider: 'twilio', id: body.sid };
}
