/** Destination checks shared by both runtimes. */

/**
 * Require an E.164 phone number, optionally restricted to country prefixes.
 *
 * SMS pumping — attacker-driven sends to premium-rate international numbers —
 * is the expensive failure mode of any SMS sender. If you only serve a few
 * countries, say so with `allowedPrefixes` (e.g. `['+1', '+44']`).
 */
export function assertE164(to: string, allowedPrefixes?: readonly string[]): string {
  const trimmed = to.trim();
  if (!/^\+[1-9]\d{6,14}$/u.test(trimmed)) {
    throw new TypeError('Destination must be an E.164 phone number (e.g. +15551234567).');
  }
  if (allowedPrefixes && !allowedPrefixes.some((prefix) => trimmed.startsWith(prefix))) {
    throw new TypeError('Destination country is not in SMS_ALLOWED_PREFIXES.');
  }
  return trimmed;
}

/** Minimal shape check; real deliverability is the provider's answer. */
export function assertEmailAddress(to: string): string {
  const trimmed = to.trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/u.test(trimmed)) {
    throw new TypeError('Destination must be an email address.');
  }
  return trimmed;
}

/** Parse `SMS_ALLOWED_PREFIXES="+1,+44"` style configuration. */
export function parseAllowedPrefixes(value: string | undefined): string[] | undefined {
  const prefixes = (value ?? '')
    .split(',')
    .map((prefix) => prefix.trim())
    .filter((prefix) => prefix.startsWith('+'));
  return prefixes.length > 0 ? prefixes : undefined;
}
