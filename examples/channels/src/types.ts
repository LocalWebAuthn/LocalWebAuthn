/** Rendered email content. Produced only by the fixed templates. */
export type EmailContent = {
  subject: string;
  text: string;
  html: string;
};

/**
 * Normalized outcome of one provider send.
 *
 * Deliberately minimal: no raw provider response bodies. `error` is a short
 * status line for the host's own logs — never return it to clients.
 */
export type DeliveryResult = {
  ok: boolean;
  provider: 'twilio' | 'resend' | 'smtp';
  /** Provider message id when the send was accepted. */
  id?: string;
  error?: string;
};

export type FetchLike = typeof fetch;
