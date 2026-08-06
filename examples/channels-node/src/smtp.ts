import type { DeliveryResult, EmailContent } from '@localwebauthn/channels-core';

import { assertEmailAddress } from '@localwebauthn/channels-core';
import { createTransport, type Transporter } from 'nodemailer';

export type SmtpConfig = {
  /**
   * SMTP URL with an application-specific password, e.g.
   * `smtps://user%40example.com:app-password@smtp.example.com:465`.
   */
  url: string;
  /** From header, e.g. `"Example" <enroll@example.com>`. */
  from: string;
};

/** One transporter per process; nodemailer pools connections internally. */
export function smtpTransport(config: SmtpConfig): Transporter {
  return createTransport(config.url);
}

/**
 * Send templated email over plain SMTP — the traditional-server transport.
 * DKIM/SPF come from your mail provider's domain setup, exactly as for any
 * other mail the server sends.
 */
export async function sendEmailSmtp(
  transporter: Transporter,
  from: string,
  to: string,
  content: EmailContent,
): Promise<DeliveryResult> {
  const destination = assertEmailAddress(to);
  try {
    const info = (await transporter.sendMail({
      from,
      to: destination,
      subject: content.subject,
      text: content.text,
      html: content.html,
    })) as { messageId?: string };
    return { ok: true, provider: 'smtp', id: info.messageId };
  } catch (error) {
    return {
      ok: false,
      provider: 'smtp',
      error: error instanceof Error ? error.message : 'SMTP send failed.',
    };
  }
}
