/**
 * The shared "internal delivery" flow both runtime examples use.
 *
 * There is deliberately no HTTP surface here: delivery is a function your
 * application calls from its own authorized routes. The interface below is
 * what each runtime implements — SMTP + Twilio on a Node server, Resend +
 * Twilio on Cloudflare Workers.
 */

import type { DeliveryResult } from './types.js';

/** Where to reach the person. At least one channel must be present. */
export type Destination = {
  email?: string;
  phone?: string;
};

/**
 * Runtime-specific senders, always wrapping the fixed templates. Implemented
 * by `channels-node` (SMTP + Twilio) and `channels-cf` (Resend + Twilio).
 */
export type EnrollmentDelivery = {
  enrollment(
    to: Destination,
    params: { url: string; expiresAt?: number },
  ): Promise<DeliveryResult[]>;
  otp(to: Destination, params: { code: string }): Promise<DeliveryResult[]>;
};

/** The one LocalWebAuthn method this flow needs. */
type IssuesEnrollment = {
  issueEnrollment(
    userId: string,
    options?: { approvedByUserId?: string },
  ): Promise<{ enrollmentUrl: string; expiresAt: number; supersededGrantIds: string[] }>;
};

export type InviteOutcome = {
  /** True when every attempted channel accepted the message. */
  delivered: boolean;
  results: DeliveryResult[];
  expiresAt: number;
  supersededGrantIds: string[];
};

/**
 * Issue a one-time enrollment grant and deliver it on the bound channels.
 *
 * The outcome intentionally omits the enrollment URL and token: the only copy
 * goes to the destination. Callers respond to their clients with
 * `{ delivered }`-shaped data, never the link.
 */
export async function inviteAndDeliver(
  auth: IssuesEnrollment,
  delivery: EnrollmentDelivery,
  input: { userId: string; to: Destination; approvedByUserId?: string },
): Promise<InviteOutcome> {
  if (!input.to.email && !input.to.phone) {
    throw new TypeError('At least one delivery channel (email or phone) is required.');
  }
  const issue = await auth.issueEnrollment(input.userId, {
    approvedByUserId: input.approvedByUserId,
  });
  const results = await delivery.enrollment(input.to, {
    url: issue.enrollmentUrl,
    expiresAt: issue.expiresAt,
  });
  return {
    delivered: results.length > 0 && results.every((result) => result.ok),
    results,
    expiresAt: issue.expiresAt,
    supersededGrantIds: issue.supersededGrantIds,
  };
}
