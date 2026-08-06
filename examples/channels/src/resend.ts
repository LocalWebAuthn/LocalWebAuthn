import type { DeliveryResult, EmailContent, FetchLike } from './types.js';

import { assertEmailAddress } from './validate.js';

export type ResendConfig = {
  apiKey: string;
  /** Sender on a domain verified in Resend (DKIM is applied there). */
  from: string;
  /** Override for tests / proxies. Default `https://api.resend.com`. */
  apiBase?: string;
};

/**
 * Send email via Resend's HTTP API — the Workers-idiomatic transport (Workers
 * cannot speak SMTP; outbound port 25 is blocked). Also usable from Node.
 *
 * @see https://resend.com/docs/api-reference/emails/send-email
 */
export async function sendEmailResend(
  config: ResendConfig,
  to: string,
  content: EmailContent,
  fetchImpl: FetchLike = fetch,
): Promise<DeliveryResult> {
  const destination = assertEmailAddress(to);
  const base = (config.apiBase ?? 'https://api.resend.com').replace(/\/+$/u, '');

  const response = await fetchImpl(`${base}/emails`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${config.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: config.from,
      to: [destination],
      subject: content.subject,
      text: content.text,
      html: content.html,
    }),
  });

  if (!response.ok) {
    return { ok: false, provider: 'resend', error: `HTTP ${String(response.status)}` };
  }
  const body = (await response.json().catch(() => ({}))) as { id?: string };
  return { ok: true, provider: 'resend', id: body.id };
}
