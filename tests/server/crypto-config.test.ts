import { describe, expect, it } from 'vitest';

import {
  createEnrollmentToken,
  createOpaqueToken,
  createUserHandle,
  decodeBase64Url,
  encodeBase32,
  encodeBase64Url,
  equalBytes,
  LocalWebAuthn,
  LocalWebAuthnError,
} from '../../packages/server/src/index.js';
import type { LocalWebAuthnOptions, LocalWebAuthnStore } from '../../packages/server/src/index.js';

const unusedStore = {} as LocalWebAuthnStore;
const users = { getUser: async () => null };

function options(overrides: Partial<LocalWebAuthnOptions> = {}): LocalWebAuthnOptions {
  return {
    rpName: 'Test',
    rpId: 'localhost',
    expectedOrigins: 'http://localhost:5173',
    store: unusedStore,
    users,
    ...overrides,
  };
}

describe('portable cryptographic helpers', () => {
  it('creates 256-bit user handles and bearer tokens', () => {
    expect(createUserHandle()).toHaveLength(32);
    expect(createEnrollmentToken()).toMatch(/^[a-z2-7]{52}$/u);
    expect(createOpaqueToken()).toMatch(/^[A-Za-z0-9_-]{43}$/u);
  });

  it('encodes known base32 and base64url values', () => {
    expect(encodeBase32(new TextEncoder().encode('foo'))).toBe('mzxw6');
    const encoded = encodeBase64Url(new Uint8Array([251, 255, 239]));
    expect(encoded).toBe('-__v');
    expect(decodeBase64Url(encoded)).toEqual(new Uint8Array([251, 255, 239]));
    expect(decodeBase64Url('not+base64')).toBeNull();
  });

  it('compares equal-length bytes without early value exits', () => {
    expect(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(equalBytes(new Uint8Array([1]), new Uint8Array([1, 0]))).toBe(false);
  });
});

describe('configuration validation', () => {
  it('normalizes exact origins and applies conservative defaults', () => {
    const auth = new LocalWebAuthn(options());
    expect(auth.config).toMatchObject({
      rpId: 'localhost',
      expectedOrigins: ['http://localhost:5173'],
      publicOrigin: 'http://localhost:5173',
      enrollmentPath: '/enroll',
    });
    expect(auth.config.durations.sessionIdleMs).toBeLessThan(
      auth.config.durations.sessionAbsoluteMs,
    );
  });

  it.each([
    { expectedOrigins: 'http://example.com' },
    { expectedOrigins: 'https://other.example', rpId: 'example.com' },
    { expectedOrigins: 'https://pulse.example.com/path', rpId: 'example.com' },
    { durations: { sessionIdleMs: 2, sessionAbsoluteMs: 1 } },
  ])('rejects unsafe configuration %#', (override) => {
    expect(() => new LocalWebAuthn(options(override))).toThrow(LocalWebAuthnError);
  });
});
