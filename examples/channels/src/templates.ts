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
