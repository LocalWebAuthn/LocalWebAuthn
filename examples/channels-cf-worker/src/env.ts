/**
 * Worker bindings for channel delivery.
 *
 * Resend applies DKIM once the sending domain is verified in their dashboard —
 * this worker does not implement DKIM itself.
 */
export type ChannelsEnv = {
  TWILIO_ACCOUNT_SID: string;
  TWILIO_AUTH_TOKEN: string;
  TWILIO_PHONE_NUMBER: string;
  RESEND_API_KEY: string;
  /** Verified domain sender, e.g. `enroll@auth.example.com`. */
  RESEND_FROM: string;
  /**
   * Optional overrides for tests / proxies.
   * Defaults: Twilio `https://api.twilio.com`, Resend `https://api.resend.com`.
   */
  TWILIO_API_BASE?: string;
  RESEND_API_BASE?: string;
};

export type FetchLike = typeof fetch;

export function requireBinding(env: ChannelsEnv, key: keyof ChannelsEnv): string {
  const value = env[key];
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`Missing required Worker binding: ${key}`);
  }
  return value;
}
