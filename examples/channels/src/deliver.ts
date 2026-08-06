/**
 * The shared "internal delivery" flow both runtime examples use.
 *
 * There is deliberately no HTTP surface here: delivery is a function your
 * application calls from its own authorized routes. The interface below is
 * what each runtime implements — SMTP + Twilio on a Node server, Resend +
 * Twilio on Cloudflare Workers.
 *
 * ## How we know delivery failed
 *
 * Each channel returns a {@link DeliveryResult}:
 * - `ok: true` — the provider accepted the message (HTTP 2xx / SMTP accepted).
 * - `ok: false` — the provider rejected it (`error` is a short status line).
 * - thrown Error — transport/config failure before a result was produced.
 *
 * `inviteAndDeliver` treats **no successful channel** as total failure and
 * revokes the pending grant so a link that never left the building cannot be
 * used later. If at least one channel accepted the message, the grant stays
 * live (partial delivery still reached the person on that channel).
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

/** LocalWebAuthn methods this flow needs. */
export type EnrollmentIssuer = {
  issueEnrollment(
    userId: string,
    approvedByUserId?: string,
  ): Promise<{
    grantId: string;
    enrollmentUrl: string;
    expiresAt: number;
    supersededGrantIds: string[];
  }>;
  /**
   * Revoke outstanding pending grants without touching credentials.
   * Required so total delivery failure can abandon the grant just issued.
   */
  revokePendingEnrollments(userId: string): Promise<string[]>;
};

export type InviteOutcome = {
  /** True when every attempted channel accepted the message. */
  delivered: boolean;
  /** True when at least one channel accepted the message. */
  anyDelivered: boolean;
  results: DeliveryResult[];
  expiresAt: number;
  supersededGrantIds: string[];
  grantId: string;
  /**
   * `live` — grant remains usable (full or partial delivery).
   * `revoked_after_delivery_failure` — no channel accepted; grant was revoked.
   */
  grantStatus: 'live' | 'revoked_after_delivery_failure';
  /** Grant IDs revoked because delivery failed completely (usually the one just issued). */
  revokedGrantIds: string[];
};

/**
 * Issue a one-time enrollment grant and deliver it on the bound channels.
 *
 * The outcome intentionally omits the enrollment URL and token: the only copy
 * goes to the destination. Callers respond to their clients with
 * `{ delivered }`-shaped data, never the link.
 *
 * When **no** channel accepts the message, pending grants for the user are
 * revoked so an undelivered bearer link cannot be exchanged later. Partial
 * success (e.g. email ok, SMS fail) keeps the grant — the person may still
 * have received the link on the working channel.
 */
export async function inviteAndDeliver(
  auth: EnrollmentIssuer,
  delivery: EnrollmentDelivery,
  input: { userId: string; to: Destination; approvedByUserId?: string },
): Promise<InviteOutcome> {
  if (!input.to.email && !input.to.phone) {
    throw new TypeError('At least one delivery channel (email or phone) is required.');
  }

  const issue = await auth.issueEnrollment(input.userId, input.approvedByUserId);

  let results: DeliveryResult[];
  try {
    results = await delivery.enrollment(input.to, {
      url: issue.enrollmentUrl,
      expiresAt: issue.expiresAt,
    });
  } catch (error) {
    const revokedGrantIds = await auth.revokePendingEnrollments(input.userId);
    const message = error instanceof Error ? error.message : 'Delivery failed.';
    return {
      delivered: false,
      anyDelivered: false,
      results: [{ ok: false, provider: 'resend', error: message }],
      expiresAt: issue.expiresAt,
      supersededGrantIds: issue.supersededGrantIds,
      grantId: issue.grantId,
      grantStatus: 'revoked_after_delivery_failure',
      revokedGrantIds,
    };
  }

  const anyDelivered = results.some((result) => result.ok);
  const delivered = results.length > 0 && results.every((result) => result.ok);

  if (!anyDelivered) {
    const revokedGrantIds = await auth.revokePendingEnrollments(input.userId);
    return {
      delivered: false,
      anyDelivered: false,
      results,
      expiresAt: issue.expiresAt,
      supersededGrantIds: issue.supersededGrantIds,
      grantId: issue.grantId,
      grantStatus: 'revoked_after_delivery_failure',
      revokedGrantIds,
    };
  }

  return {
    delivered,
    anyDelivered: true,
    results,
    expiresAt: issue.expiresAt,
    supersededGrantIds: issue.supersededGrantIds,
    grantId: issue.grantId,
    grantStatus: 'live',
    revokedGrantIds: [],
  };
}
