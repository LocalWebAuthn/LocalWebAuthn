/**
 * Self-serve signup proofing: the state machine between "visitor submitted
 * some identifiers" and "issueEnrollment may run".
 *
 * Each link-borne channel receives one **signup-proof link** carrying the
 * signup id and that channel's OTP in the URL fragment. Opening a link and
 * pressing Confirm proves control of that channel. When the last required
 * channel is proved, the host mints the enrollment grant and returns it to
 * the completing browser — and from that moment, **presenting any channel's
 * OTP again claims the same enrollment** (`'completed'`). One message per
 * channel, total: the person finishes on whichever device they prefer,
 * regardless of which channel they happened to confirm last.
 *
 * All the opened proof pages cooperate on this one machine: each page can
 * re-present its own OTP to observe progress (`'already_proved'` carries
 * "still waiting", `'completed'` carries the claim), so a page left open
 * flips to "create your passkey" the moment the final channel confirms.
 *
 * Channels are arbitrary identifiers. The link-borne kind (email, SMS, a chat
 * DM) is proved by OTP possession through {@link verifySignupProof}. A
 * **host-attested** kind is proved by the host directly setting
 * `provedAt[channel]` from its own evidence — a WebAuthn assertion over an
 * existing passkey during re-enrollment, a TOTP, a code on a postal letter.
 * {@link signupSatisfied} ranges over the full required set either way.
 *
 * The enrollment token does not exist until proofing completes, so the links
 * are capability-free while they ride email and SMS. The deliberate tradeoff
 * of claim-on-reopen is that after completion a compromised channel holds a
 * path to the one live, single-use enrollment; a legitimate user's failed
 * exchange (token already spent) is therefore a loud support signal, never a
 * silent loss. Claims end at the signup's expiry.
 *
 * This module is pure logic + crypto: the host owns the storage (one table)
 * and the routes. See `examples/demo` for a complete simulated flow.
 */

/** Channel identifier, e.g. `'email'`, `'phone'`, or a host-attested id. */
export type SignupChannel = string;

export type SignupChallenge<Channel extends SignupChannel = SignupChannel> = {
  /** Opaque signup id; safe to show, useless without an OTP. */
  signupId: string;
  expiresAt: number;
  /** Raw per-channel OTPs — deliver them inside the proof links, then forget. */
  otps: Record<Channel, string>;
  /** SHA-256 of each OTP — store these, never the raw values. */
  otpHashes: Record<Channel, Uint8Array>;
};

/** What the host persists per signup, alongside its own user fields. */
export type SignupProofState = {
  expiresAt: number;
  /** Unix ms per channel once proved, else null/absent. */
  provedAt: Partial<Record<SignupChannel, number | null>>;
  /** Set when enrollment was issued; from then on valid OTPs claim it. */
  consumedAt: number | null;
};

const TOKEN_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

function randomToken(length: number, randomBytes: (length: number) => Uint8Array): string {
  const bytes = randomBytes(length);
  let output = '';
  for (const byte of bytes) {
    output += TOKEN_ALPHABET[byte % TOKEN_ALPHABET.length];
  }
  return output;
}

async function sha256(value: string): Promise<Uint8Array> {
  return new Uint8Array(
    await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)),
  );
}

function defaultRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Mint a signup id and one OTP per **link-borne** channel (32 random base32
 * characters each — link-carried, so length costs the user nothing).
 * Host-attested channels get no OTP; the host proves them itself.
 */
export async function createSignupChallenge<Channel extends SignupChannel>(
  channels: readonly Channel[],
  options: {
    /** Proofing window; default 15 minutes. */
    ttlMs?: number;
    now?: number;
    randomBytes?: (length: number) => Uint8Array;
  } = {},
): Promise<SignupChallenge<Channel>> {
  if (channels.length === 0) {
    throw new TypeError('At least one signup channel is required.');
  }
  const randomBytes = options.randomBytes ?? defaultRandomBytes;
  const now = options.now ?? Date.now();
  const otps = {} as Record<Channel, string>;
  const otpHashes = {} as Record<Channel, Uint8Array>;
  for (const channel of channels) {
    const otp = randomToken(32, randomBytes);
    otps[channel] = otp;
    otpHashes[channel] = await sha256(otp);
  }
  return {
    signupId: randomToken(26, randomBytes),
    expiresAt: now + (options.ttlMs ?? 15 * 60_000),
    otps,
    otpHashes,
  };
}

/**
 * Proof link for one channel. The payload rides the fragment, like enrollment
 * URLs: it never reaches server logs or Referer headers.
 */
export function signupProofUrl(
  publicOrigin: string,
  signupId: string,
  channel: SignupChannel,
  otp: string,
  path = '/signup',
): string {
  const url = new URL(path, publicOrigin);
  url.hash = `signup=${signupId}&channel=${encodeURIComponent(channel)}&otp=${otp}`;
  return url.toString();
}

/**
 * Parse a proof link fragment in the browser; `null` when it is not one. The
 * channel comes back as a plain string — hosts check it against their own
 * required set.
 */
export function parseSignupFragment(
  hash: string,
): { signupId: string; channel: SignupChannel; otp: string } | null {
  const parameters = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
  const signupId = parameters.get('signup');
  const channel = parameters.get('channel');
  const otp = parameters.get('otp');
  if (!signupId || !channel || !otp) {
    return null;
  }
  return { signupId, channel, otp };
}

export type ProofOutcome = 'proved' | 'already_proved' | 'invalid' | 'expired' | 'completed';

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  let difference = left.length === right.length ? 0 : 1;
  for (const [index, byte] of left.entries()) {
    difference |= byte ^ (right[index] ?? 0);
  }
  return difference === 0;
}

/**
 * Judge one presented OTP against the stored state. Pure — the host applies
 * the transition (set `provedAt[channel] = now`) only on `'proved'`.
 *
 * `'completed'` means a valid channel OTP was presented after the signup
 * finished: the claim-on-reopen path. The host responds with the stored
 * enrollment token so the person can enroll on this device. Expiry is checked
 * first, so claims end when the signup does. Re-presenting an already-proved
 * OTP before completion returns `'already_proved'` — the polling signal for
 * "still waiting on other channels".
 */
export async function verifySignupProof(
  stored: SignupProofState & { otpHashes: Partial<Record<SignupChannel, Uint8Array>> },
  presented: { channel: SignupChannel; otp: string },
  now: number,
): Promise<ProofOutcome> {
  if (now >= stored.expiresAt) {
    return 'expired';
  }
  const expected = stored.otpHashes[presented.channel];
  if (!expected || !bytesEqual(await sha256(presented.otp), expected)) {
    return 'invalid';
  }
  if (stored.consumedAt !== null) {
    return 'completed';
  }
  if (stored.provedAt[presented.channel]) {
    return 'already_proved';
  }
  return 'proved';
}

/** True when every required channel (link-borne or host-attested) is proved. */
export function signupSatisfied(
  required: readonly SignupChannel[],
  state: SignupProofState,
): boolean {
  return required.every((channel) => Boolean(state.provedAt[channel]));
}

/** Channels still awaiting proof, for "now open the link we sent to…" UI. */
export function signupMissing(
  required: readonly SignupChannel[],
  state: SignupProofState,
): SignupChannel[] {
  return required.filter((channel) => !state.provedAt[channel]);
}
