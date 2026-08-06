import { describe, expect, it } from 'vitest';

import {
  createSignupChallenge,
  parseSignupFragment,
  signupMissing,
  signupProofEmail,
  signupProofSms,
  signupProofUrl,
  signupSatisfied,
  verifySignupProof,
  type SignupProofState,
} from '../src/index.js';

const now = 1_000_000;

async function challenge() {
  let seed = 1;
  return createSignupChallenge(['email', 'phone'], {
    now,
    randomBytes: (length) => new Uint8Array(length).fill(seed++),
  });
}

describe('signup proofing state machine', () => {
  it('mints per-channel OTPs, hashes for storage, and fragment-borne links', async () => {
    const created = await challenge();
    expect(created.signupId).toMatch(/^[a-z2-7]{26}$/u);
    expect(created.otps.email).toMatch(/^[a-z2-7]{32}$/u);
    expect(created.otps.phone).toMatch(/^[a-z2-7]{32}$/u);
    expect(created.otps.email).not.toBe(created.otps.phone);
    expect(created.expiresAt).toBe(now + 15 * 60_000);

    const url = signupProofUrl(
      'https://app.example.test',
      created.signupId,
      'email',
      created.otps.email,
    );
    expect(url).toBe(
      `https://app.example.test/signup#signup=${created.signupId}&channel=email&otp=${created.otps.email}`,
    );
    expect(parseSignupFragment(new URL(url).hash)).toEqual({
      signupId: created.signupId,
      channel: 'email',
      otp: created.otps.email,
    });
    expect(parseSignupFragment('#token=abc')).toBeNull();
  });

  it('judges proofs: proved, invalid, replay, expiry, and consumption', async () => {
    const created = await challenge();
    const state: SignupProofState & { otpHashes: typeof created.otpHashes } = {
      expiresAt: created.expiresAt,
      provedAt: { email: null, phone: null },
      consumedAt: null,
      otpHashes: created.otpHashes,
    };

    await expect(
      verifySignupProof(state, { channel: 'email', otp: created.otps.email }, now),
    ).resolves.toBe('proved');
    // The OTP for one channel proves nothing on the other.
    await expect(
      verifySignupProof(state, { channel: 'phone', otp: created.otps.email }, now),
    ).resolves.toBe('invalid');
    await expect(verifySignupProof(state, { channel: 'email', otp: 'wrong' }, now)).resolves.toBe(
      'invalid',
    );

    state.provedAt.email = now;
    await expect(
      verifySignupProof(state, { channel: 'email', otp: created.otps.email }, now),
    ).resolves.toBe('already_proved');
    expect(signupSatisfied(['email', 'phone'], state)).toBe(false);
    expect(signupMissing(['email', 'phone'], state)).toEqual(['phone']);

    state.provedAt.phone = now + 1;
    expect(signupSatisfied(['email', 'phone'], state)).toBe(true);

    await expect(
      verifySignupProof(
        { ...state, provedAt: { email: null, phone: null } },
        { channel: 'phone', otp: created.otps.phone },
        created.expiresAt,
      ),
    ).resolves.toBe('expired');

    // Claim-on-reopen: after completion a valid OTP claims; an invalid one
    // still learns nothing, and claims end at expiry.
    const completed = { ...state, consumedAt: now + 2 };
    await expect(
      verifySignupProof(completed, { channel: 'phone', otp: created.otps.phone }, now),
    ).resolves.toBe('completed');
    await expect(
      verifySignupProof(completed, { channel: 'phone', otp: 'wrong' }, now),
    ).resolves.toBe('invalid');
    await expect(
      verifySignupProof(
        completed,
        { channel: 'phone', otp: created.otps.phone },
        created.expiresAt,
      ),
    ).resolves.toBe('expired');
  });

  it('renders capability-free proof copy', async () => {
    const created = await challenge();
    const url = signupProofUrl(
      'https://app.example.test',
      created.signupId,
      'email',
      created.otps.email,
    );
    const email = signupProofEmail({ appName: 'Example', url });
    expect(email.subject).toBe('Confirm your email for Example');
    expect(email.text).toContain(url);
    expect(email.text).not.toContain('enroll#token');
    expect(signupProofSms({ appName: 'Example', url })).toContain(url);
  });
});
