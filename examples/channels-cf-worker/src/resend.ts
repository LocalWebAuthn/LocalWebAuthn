import type { ChannelsEnv, FetchLike } from './env.js';
import { requireBinding } from './env.js';

export type SendEmailInput = {
  to: string;
  subject: string;
  html: string;
  /** Optional plain-text part. */
  text?: string;
};

export type SendEmailResult = {
  ok: boolean;
  status: number;
  body: string;
};

/**
 * Send email via Resend.
 *
 * DKIM: configure and verify your domain in the Resend dashboard; outbound mail
 * from that domain is signed automatically. This helper only calls the HTTP API.
 *
 * @see https://resend.com/docs/api-reference/emails/send-email
 */
export async function sendEmail(
  env: ChannelsEnv,
  input: SendEmailInput,
  fetchImpl: FetchLike = fetch,
): Promise<SendEmailResult> {
  const apiKey = requireBinding(env, 'RESEND_API_KEY');
  const from = requireBinding(env, 'RESEND_FROM');
  const base = (env.RESEND_API_BASE ?? 'https://api.resend.com').replace(/\/+$/u, '');
  const endpoint = `${base}/emails`;

  const response = await fetchImpl(endpoint, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from,
      to: [input.to],
      subject: input.subject,
      html: input.html,
      ...(input.text ? { text: input.text } : {}),
    }),
  });

  return {
    ok: response.ok,
    status: response.status,
    body: await response.text(),
  };
}
