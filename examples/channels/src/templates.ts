/**
 * The only place message content exists.
 *
 * Every send in these examples goes through a fixed template: callers supply
 * parameters (a URL, a code), never subject lines or markup. A bug or leaked
 * credential can therefore at worst emit *these* messages — it cannot turn
 * the sender into an arbitrary-content relay from your domain or number.
 */

import type { EmailContent } from './types.js';

export type EnrollmentParams = {
  /** Human name of your application, shown in the copy. */
  appName: string;
  /** One-time enrollment URL from `issueEnrollment` (with `#token=`). */
  url: string;
  /** Expiry from `issueEnrollment`, for the copy only. */
  expiresAt?: number;
};

export type OtpParams = {
  appName: string;
  /** Short-lived one-time code generated and stored (hashed) by the host. */
  code: string;
};

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function expiryLine(expiresAt?: number): string {
  if (!expiresAt) {
    return 'The link can be used once.';
  }
  return `The link can be used once and expires ${new Date(expiresAt).toISOString()}.`;
}

/**
 * The signup deadline, stated as the two things it actually bounds.
 *
 * A proof link's expiry ends the ability to use it *and* the ability to cancel with it,
 * because the veto and the claim share one clock. Saying only "this expires at X" tells
 * somebody when they lose the setup; it does not tell them they are also losing the only
 * self-serve way to stop a setup they did not start.
 */
function signupWindowLine(expiresAt?: number): string {
  const deadline = expiresAt
    ? ` You have until ${new Date(expiresAt).toISOString()}.`
    : ' The link expires shortly.';
  return `If this was not you, open the link and choose Cancel — that stops the signup and revokes any passkey it has already created.${deadline}`;
}

/** Email carrying a one-time passkey enrollment link. */
export function enrollmentEmail(params: EnrollmentParams): EmailContent {
  const subject = `Create your ${params.appName} passkey`;
  const text = [
    `You have been invited to ${params.appName}.`,
    '',
    `Open this one-time link on the device you want to sign in with:`,
    params.url,
    '',
    expiryLine(params.expiresAt),
    `${params.appName} will never ask for a password — sign-in is a passkey on your device.`,
  ].join('\n');
  const html = [
    `<p>You have been invited to <strong>${escapeHtml(params.appName)}</strong>.</p>`,
    `<p>Open this one-time link on the device you want to sign in with:</p>`,
    `<p><a href="${escapeHtml(params.url)}">${escapeHtml(params.url)}</a></p>`,
    `<p>${escapeHtml(expiryLine(params.expiresAt))}</p>`,
    `<p>${escapeHtml(params.appName)} will never ask for a password — sign-in is a passkey on your device.</p>`,
  ].join('\n');
  return { subject, text, html };
}

/** SMS carrying a one-time passkey enrollment link. */
export function enrollmentSms(params: EnrollmentParams): string {
  return `${params.appName}: create your passkey with this one-time link: ${params.url}`;
}

/** Email carrying a channel-proof code (signup verification, not login). */
export function otpEmail(params: OtpParams): EmailContent {
  const subject = `${params.appName} verification code`;
  const text = [
    `Your ${params.appName} verification code is: ${params.code}`,
    '',
    'It proves you control this address during signup. It is not a login code;',
    `${params.appName} signs in with passkeys only. Never share it.`,
  ].join('\n');
  const html = [
    `<p>Your ${escapeHtml(params.appName)} verification code is:</p>`,
    `<p style="font-size:1.5em"><strong>${escapeHtml(params.code)}</strong></p>`,
    `<p>It proves you control this address during signup. It is not a login code;`,
    ` ${escapeHtml(params.appName)} signs in with passkeys only. Never share it.</p>`,
  ].join('\n');
  return { subject, text, html };
}

/** SMS carrying a channel-proof code. */
export function otpSms(params: OtpParams): string {
  return `${params.appName} verification code: ${params.code}. Never share it.`;
}

export type SignupProofParams = {
  appName: string;
  /** Proof link from `signupProofUrl` — confirms one channel, grants nothing. */
  url: string;
  /**
   * The signup's `expiresAt`, for the copy.
   *
   * Worth stating because it is **two** deadlines at once, not one. The same instant
   * ends the ability to open this link *and* the ability to cancel with it — the veto
   * lasts exactly as long as a claim does, by construction. Somebody who needs to stop
   * a setup they did not start has to know how long they have.
   */
  expiresAt?: number;
};

/** Email carrying a signup channel-proof link (capability-free until completion). */
export function signupProofEmail(params: SignupProofParams): EmailContent {
  const subject = `Confirm your email for ${params.appName}`;
  const text = [
    `Someone (hopefully you) is signing up for ${params.appName} with this address.`,
    '',
    'Open this link to confirm you control it:',
    params.url,
    '',
    'Once every channel is confirmed, this same link opens your passkey setup —',
    'use it on the device where you want to sign in.',
    '',
    signupWindowLine(params.expiresAt),
  ].join('\n');
  const html = [
    `<p>Someone (hopefully you) is signing up for <strong>${escapeHtml(params.appName)}</strong> with this address.</p>`,
    `<p>Open this link to confirm you control it:</p>`,
    `<p><a href="${escapeHtml(params.url)}">${escapeHtml(params.url)}</a></p>`,
    `<p>Once every channel is confirmed, this same link opens your passkey setup —`,
    ` use it on the device where you want to sign in.</p>`,
    `<p>${escapeHtml(signupWindowLine(params.expiresAt))}</p>`,
  ].join('\n');
  return { subject, text, html };
}

/** SMS carrying a signup channel-proof link (capability-free until completion). */
export function signupProofSms(params: SignupProofParams): string {
  const deadline = params.expiresAt ? ` until ${new Date(params.expiresAt).toISOString()}` : '';
  return `${params.appName}: confirm this phone: ${params.url} - after all confirmations the same link sets up your passkey. Not you? Open it and Cancel${deadline} to stop the signup and revoke any passkey it created.`;
}

export type PasskeyCreatedParams = {
  appName: string;
  /** How the person should describe the credential, e.g. its label. */
  label: string;
  /** The authority that committed this credential registration. */
  createdVia: 'enrollment' | 'credential';
  /** Where to go if they did not do this. */
  supportContact: string;
};

/**
 * Sent to **every** channel bound to a person the moment a passkey is created for
 * their account.
 *
 * This is the one notice that does not depend on anybody noticing anything. Every
 * other signal in this system is *pulled*: it reaches the person only if they come
 * back and try something that fails. An attacker who obtains an enrollment link and
 * uses it leaves an account that looks entirely normal — so if the rightful person
 * never returns, nothing tells them. Announcing the credential itself closes that,
 * because the state everyone actually cares about is "a passkey now exists".
 *
 * It fires on legitimate enrollments too, which is the point rather than a cost. A
 * person who just created a passkey reads it and moves on; a person who did not
 * reads it and acts. Only the second one needed to be reached, and there is no way
 * to know in advance which they are.
 *
 * The remedy names the authority the service actually used. An enrollment-derived
 * credential points to an invitation; a credential-derived one points to a signed-in
 * session. Neither path guesses how that authority was obtained.
 */
export function passkeyCreatedEmail(params: PasskeyCreatedParams): EmailContent {
  const subject = `A credential was added to your ${params.appName} account`;
  const unexpected =
    params.createdVia === 'enrollment'
      ? [
          'If it was NOT you, someone used an enrollment invitation for your account.',
          'The service cannot tell how they obtained it. Act in this order:',
        ]
      : [
          'If it was NOT you, it was added from a signed-in session for your account.',
          'Treat that session and any other live sessions as compromised. Act in this order:',
        ];
  const text = [
    `A credential ("${params.label}") was just added to your ${params.appName} account.`,
    '',
    'If that was you, nothing more is needed — you can sign in with it from now on.',
    '',
    ...unexpected,
    '',
    `  1. Contact ${params.supportContact} and ask them to lock the account and`,
    '     revoke the credential that was just added and every live session.',
    params.createdVia === 'enrollment'
      ? '  2. Cancel other pending invitations and investigate how this one was exposed.'
      : '  2. Investigate how the signed-in session was obtained and secure that device.',
    '  3. Re-secure email or phone if the investigation shows either channel was exposed.',
  ].join('\n');
  const authorization =
    params.createdVia === 'enrollment'
      ? 'someone used an enrollment invitation for your account. The service cannot tell how they obtained it'
      : 'it was added from a signed-in session for your account. Treat that session and any other live sessions as compromised';
  const html = [
    `<p>A credential (<strong>${escapeHtml(params.label)}</strong>) was just added to your <strong>${escapeHtml(params.appName)}</strong> account.</p>`,
    `<p>If that was you, nothing more is needed — you can sign in with it from now on.</p>`,
    `<p>If it was <strong>not</strong> you, ${authorization}. Act in this order:</p>`,
    '<ol>',
    `<li>Contact ${escapeHtml(params.supportContact)} and ask them to lock the account, revoke the credential that was just added, and revoke every live session.</li>`,
    params.createdVia === 'enrollment'
      ? '<li>Cancel other pending invitations and investigate how this one was exposed.</li>'
      : '<li>Investigate how the signed-in session was obtained and secure that device.</li>',
    '<li>Re-secure email or phone if the investigation shows either channel was exposed.</li>',
    '</ol>',
  ].join('\n');
  return { subject, text, html };
}

/** SMS form of {@link passkeyCreatedEmail}. */
export function passkeyCreatedSms(params: PasskeyCreatedParams): string {
  const authority =
    params.createdVia === 'enrollment' ? 'an enrollment invitation' : 'a signed-in session';
  return `${params.appName}: a credential ("${params.label}") was added using ${authority}. Not you? Contact ${params.supportContact} to lock the account and revoke the credential and live sessions.`;
}

export type SignupCanceledParams = {
  appName: string;
  /** True when the veto also revoked credentials the signup had produced. */
  revokedAccess: boolean;
  supportContact: string;
};

/**
 * Sent to **every** bound channel when a signup is vetoed.
 *
 * Any one channel can cancel, so whoever reads this may not be whoever used it. That
 * cuts both ways, and the message has to serve both readers: somebody part-way through
 * a setup needs to know why their link stopped working rather than concluding the
 * service is broken, and somebody who did not cancel needs to know that a person who
 * can reach one of their channels just took an action on their account.
 *
 * When the veto arrives after a credential already exists it revokes it, which changes
 * what has to be said — a working credential just stopped working. The copy therefore
 * splits on {@link SignupCanceledParams.revokedAccess} instead of hedging over both.
 *
 * The unexpected-cancel branch can be specific in a way most of these cannot:
 * cancelling *requires* a channel OTP, so an unexplained cancel is direct evidence that
 * somebody reaches email or phone. No other notice in this set can narrow it that far.
 */
export function signupCanceledEmail(params: SignupCanceledParams): EmailContent {
  const subject = `Your ${params.appName} setup was cancelled`;
  const lead = params.revokedAccess
    ? `A setup for your ${params.appName} account was cancelled, and the credential it had created has been revoked. Nothing that setup produced can sign in.`
    : `A setup for your ${params.appName} account was cancelled before it finished.`;
  const text = [
    lead,
    '',
    'If you cancelled it, nothing more is needed. Ask for a new invitation when you are',
    'ready.',
    '',
    'If you did NOT cancel it, somebody else can reach your email or your phone —',
    'cancelling requires one of them. Act in this order:',
    '',
    `  1. Contact ${params.supportContact} before asking for another invitation.`,
    '  2. Re-secure your email and phone.',
    '  3. Ask for a new invitation once both are back under your control.',
  ].join('\n');
  const html = [
    `<p>${escapeHtml(lead)}</p>`,
    '<p>If you cancelled it, nothing more is needed. Ask for a new invitation when you are ready.</p>',
    '<p>If you did <strong>not</strong> cancel it, somebody else can reach your email or your phone — cancelling requires one of them. Act in this order:</p>',
    '<ol>',
    `<li>Contact ${escapeHtml(params.supportContact)} before asking for another invitation.</li>`,
    '<li>Re-secure your email and phone.</li>',
    '<li>Ask for a new invitation once both are back under your control.</li>',
    '</ol>',
  ].join('\n');
  return { subject, text, html };
}

/** SMS form of {@link signupCanceledEmail}. */
export function signupCanceledSms(params: SignupCanceledParams): string {
  const what = params.revokedAccess
    ? 'was cancelled and its credential revoked'
    : 'was cancelled before it finished';
  return `${params.appName}: your account setup ${what}. Not you? Cancelling needs your email or phone, so somebody can reach one - contact ${params.supportContact} and re-secure both.`;
}
