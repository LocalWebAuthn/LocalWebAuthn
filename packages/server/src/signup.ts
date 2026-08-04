/**
 * Host-owned passkey signup / enrollment sequencing.
 *
 * LocalWebAuthn stores grants, credentials, and sessions — not application
 * users. This module does not write to the database. It names the phases a
 * host app moves through so signup UIs and APIs share one vocabulary and do
 * not invent ad-hoc “pending” flags that drift from the store.
 *
 * Typical happy path:
 *
 * 1. Host creates a user row with {@link createUserHandle} (phase `created`).
 * 2. Host proves channels / admin approval as product policy.
 * 3. Host calls `issueEnrollment` (phase `enrollment_issued`).
 * 4. Browser opens the fragment, `exchangeEnrollment` (phase `enrollment_exchanged`).
 * 5. `verifyRegistration` creates a credential (phase `enrolled`).
 *
 * Recovery returns to `enrollment_issued` after `revokeUserAuthentication`
 * plus a new `issueEnrollment` (see demo **Re-enroll**).
 */

export type SignupPhase = 'created' | 'enrollment_issued' | 'enrollment_exchanged' | 'enrolled';

/**
 * Observable facts the host can load without guessing.
 *
 * - `hasActiveCredential` — `listCredentials(userId).length > 0`
 * - `hasPendingEnrollmentGrant` — host tracks issued grants, or treats a
 *   non-null enrollment session / product “pending invite” flag as true
 * - `hasEnrollmentSession` — browser has a valid enrollment cookie (host may
 *   only know this on register routes)
 */
export type SignupFacts = {
  hasActiveCredential: boolean;
  hasPendingEnrollmentGrant: boolean;
  hasEnrollmentSession: boolean;
};

/**
 * Derive the current signup phase from store/session facts.
 *
 * Credentials win: once a passkey exists, the user is `enrolled` even if an
 * old grant row still exists until cleanup.
 */
export function signupPhase(facts: SignupFacts): SignupPhase {
  if (facts.hasActiveCredential) {
    return 'enrolled';
  }
  if (facts.hasEnrollmentSession) {
    return 'enrollment_exchanged';
  }
  if (facts.hasPendingEnrollmentGrant) {
    return 'enrollment_issued';
  }
  return 'created';
}

export type SignupNextStep =
  | { action: 'issue_enrollment'; reason: string }
  | { action: 'deliver_enrollment_url'; reason: string }
  | { action: 'register_passkey'; reason: string }
  | { action: 'done'; reason: string };

/**
 * Human-oriented next step for admin UIs and automated signup workers.
 */
export function nextSignupStep(phase: SignupPhase): SignupNextStep {
  switch (phase) {
    case 'created':
      return {
        action: 'issue_enrollment',
        reason: 'Create a one-time enrollment grant after your identity checks pass.',
      };
    case 'enrollment_issued':
      return {
        action: 'deliver_enrollment_url',
        reason: 'Deliver the enrollment URL on a channel bound to the person; wait for exchange.',
      };
    case 'enrollment_exchanged':
      return {
        action: 'register_passkey',
        reason: 'Browser should call register options/verify to create the first passkey.',
      };
    case 'enrolled':
      return {
        action: 'done',
        reason: 'User has an active passkey; use session auth and optional additional passkeys.',
      };
  }
}

/**
 * Short description for logs and admin tables.
 */
export function describeSignupPhase(phase: SignupPhase): string {
  switch (phase) {
    case 'created':
      return 'User exists; no enrollment grant yet';
    case 'enrollment_issued':
      return 'Enrollment link outstanding; no passkey yet';
    case 'enrollment_exchanged':
      return 'Enrollment session active; passkey registration in progress';
    case 'enrolled':
      return 'At least one active passkey';
  }
}

/**
 * Recommended host steps for automated self-serve signup (no standing email login).
 *
 * Implementations prove channels first, then call LocalWebAuthn — this list is
 * the contract, not executable I/O.
 */
export const SELF_SERVE_SIGNUP_STEPS = [
  'Collect identifiers (e.g. email and phone) and rate-limit the form',
  'Verify control of two independent channels before creating durable access',
  'Insert application user with createUserHandle(); do not store a password',
  'Call issueEnrollment(userId); store only the URL for delivery, never log the raw token long-term',
  'Deliver the enrollment URL on a bound channel (not an attacker-supplied address)',
  'User opens fragment → exchangeEnrollment → registerPasskey',
  'Optionally prompt for a second passkey while the session is fresh',
] as const;
