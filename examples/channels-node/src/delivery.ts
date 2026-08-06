/**
 * Traditional-server delivery: SMTP (application password) + Twilio SMS.
 *
 * This module is the whole security model for a Node host: delivery is an
 * in-process function that only your own routes can call. There is no send
 * endpoint to protect, and all content comes from the fixed templates.
 */

import type {
  Destination,
  DeliveryResult,
  EnrollmentDelivery,
  FetchLike,
  TwilioConfig,
} from '@localwebauthn/channels-core';
import type { Transporter } from 'nodemailer';

import {
  enrollmentEmail,
  enrollmentSms,
  otpEmail,
  otpSms,
  parseAllowedPrefixes,
  sendSms,
} from '@localwebauthn/channels-core';

import { sendEmailSmtp, smtpTransport } from './smtp.js';

export type NodeDeliveryEnv = {
  APP_NAME?: string;
  SMTP_URL?: string;
  SMTP_FROM?: string;
  TWILIO_ACCOUNT_SID?: string;
  TWILIO_AUTH_TOKEN?: string;
  TWILIO_PHONE_NUMBER?: string;
  /** Comma-separated country prefixes, e.g. `+1,+44`. Strongly recommended. */
  SMS_ALLOWED_PREFIXES?: string;
};

export type NodeDelivery = EnrollmentDelivery & {
  /** Which channels this environment can actually reach. */
  channels: { email: boolean; sms: boolean };
};

/** Test seams; production callers omit this argument entirely. */
export type NodeDeliveryOverrides = {
  transporter?: Transporter;
  fetchImpl?: FetchLike;
};

/**
 * Build delivery from the environment. Channels without configuration are
 * simply absent — attempting to use one is an error, not a silent skip.
 */
export function createDelivery(
  env: NodeDeliveryEnv = process.env,
  overrides: NodeDeliveryOverrides = {},
): NodeDelivery {
  const appName = env.APP_NAME ?? 'LocalWebAuthn example';

  const smtp =
    env.SMTP_URL && env.SMTP_FROM
      ? {
          transporter:
            overrides.transporter ?? smtpTransport({ url: env.SMTP_URL, from: env.SMTP_FROM }),
          from: env.SMTP_FROM,
        }
      : undefined;

  const twilio: TwilioConfig | undefined =
    env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN && env.TWILIO_PHONE_NUMBER
      ? {
          accountSid: env.TWILIO_ACCOUNT_SID,
          authToken: env.TWILIO_AUTH_TOKEN,
          from: env.TWILIO_PHONE_NUMBER,
          allowedPrefixes: parseAllowedPrefixes(env.SMS_ALLOWED_PREFIXES),
        }
      : undefined;

  async function sendBoth(
    to: Destination,
    email: () => Parameters<typeof sendEmailSmtp>[3],
    sms: () => string,
  ): Promise<DeliveryResult[]> {
    const results: DeliveryResult[] = [];
    if (to.email) {
      if (!smtp) {
        throw new Error('Email delivery requested but SMTP_URL / SMTP_FROM are not configured.');
      }
      results.push(await sendEmailSmtp(smtp.transporter, smtp.from, to.email, email()));
    }
    if (to.phone) {
      if (!twilio) {
        throw new Error('SMS delivery requested but TWILIO_* is not configured.');
      }
      results.push(await sendSms(twilio, { to: to.phone, body: sms() }, overrides.fetchImpl));
    }
    return results;
  }

  return {
    channels: { email: smtp !== undefined, sms: twilio !== undefined },
    enrollment: (to, params) =>
      sendBoth(
        to,
        () => enrollmentEmail({ appName, ...params }),
        () => enrollmentSms({ appName, ...params }),
      ),
    otp: (to, params) =>
      sendBoth(
        to,
        () => otpEmail({ appName, ...params }),
        () => otpSms({ appName, ...params }),
      ),
  };
}
