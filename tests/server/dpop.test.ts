/**
 * Every way a DPoP proof can be rejected, and both key types it can carry.
 *
 * Table-driven on purpose. A verifier whose rejection paths are untested is a
 * verifier whose *acceptance* is unproven: nothing shows it refuses for the reason
 * it claims rather than incidentally, and nothing stops a future edit collapsing
 * two distinct failures into one. Each case here starts from a proof that verifies
 * and applies the smallest change that should break it.
 */

import { describe, expect, it } from 'vitest';

import {
  createDpopProof,
  EDDSA,
  ES256,
  encodeBase64Url,
  type MachineKeyStore,
  sha256,
  utf8,
} from '../../packages/client/src/index.js';
import { generateKeyStore } from '../../packages/client/src/file-key.js';
import {
  coseToJwk,
  type DpopVerificationInput,
  jwkThumbprint,
  verifyDpopProof,
} from '../../packages/server/src/index.js';

const URL_UNDER_TEST = 'https://app.example.test/api/reports';
const TOKEN = 'session-token';

async function baseline(algorithm: -7 | -8 = ES256): Promise<{
  keyStore: MachineKeyStore;
  input: DpopVerificationInput;
}> {
  const { keyStore } = await generateKeyStore(algorithm);
  return {
    keyStore,
    input: {
      proof: await createDpopProof({
        keyStore,
        method: 'POST',
        url: URL_UNDER_TEST,
        accessToken: TOKEN,
      }),
      method: 'POST',
      url: URL_UNDER_TEST,
      accessToken: TOKEN,
      publicKeyCose: await keyStore.publicKeyCose(),
    },
  };
}

/** Re-sign a proof from explicit header and payload objects, or raw segments. */
async function forge(
  keyStore: MachineKeyStore,
  parts: { header?: unknown; payload?: unknown; rawHeader?: string; rawPayload?: string },
): Promise<string> {
  const header =
    parts.rawHeader ??
    encodeBase64Url(
      utf8(
        JSON.stringify(
          parts.header ?? {
            typ: 'dpop+jwt',
            alg: keyStore.algorithm === ES256 ? 'ES256' : 'EdDSA',
            jwk: await keyStore.publicJwk(),
          },
        ),
      ),
    );
  const payload =
    parts.rawPayload ??
    encodeBase64Url(
      utf8(
        JSON.stringify(
          parts.payload ?? {
            jti: 'a'.repeat(16),
            htm: 'POST',
            htu: URL_UNDER_TEST,
            iat: Math.floor(Date.now() / 1000),
            ath: encodeBase64Url(await sha256(TOKEN)),
          },
        ),
      ),
    );
  const signingInput = `${header}.${payload}`;
  return `${signingInput}.${encodeBase64Url(await keyStore.signJws(utf8(signingInput)))}`;
}

describe('a proof that should verify', () => {
  it('verifies, and yields a jti digest to claim', async () => {
    const { input } = await baseline();
    const verification = await verifyDpopProof(input);
    expect(verification).toMatchObject({ valid: true });
    if (verification.valid) {
      expect(verification.jtiHash).toHaveLength(32);
      expect(verification.expiresAt).toBeGreaterThan(Date.now());
    }
  });

  it('verifies an Ed25519 proof', async () => {
    // EDDSA is an exported constant, so the OKP path has to be exercised or the
    // export is a claim nothing backs.
    const { input } = await baseline(EDDSA);
    await expect(verifyDpopProof(input)).resolves.toMatchObject({ valid: true });
  });
});

describe('rejections, by reason', () => {
  /**
   * Each case returns the input to verify. Header checks run before signature
   * verification, so those cases may corrupt the header without re-signing;
   * payload checks run after it, so those must re-sign or they would fail as
   * `bad_signature` and prove nothing about the payload rule.
   */
  const cases: Record<string, () => Promise<DpopVerificationInput> | DpopVerificationInput> = {
    malformed_proof: async () => ({ ...(await baseline()).input, proof: 'only.two' }),

    malformed_header: async () => {
      const { input } = await baseline();
      const [, payload, signature] = input.proof.split('.');
      return { ...input, proof: `bm90LWpzb24.${payload}.${signature}` };
    },

    unexpected_typ: async () => {
      const { keyStore, input } = await baseline();
      return {
        ...input,
        proof: await forge(keyStore, {
          header: { typ: 'jwt', alg: 'ES256', jwk: await keyStore.publicJwk() },
        }),
      };
    },

    unsupported_alg: async () => {
      const { keyStore, input } = await baseline();
      return {
        ...input,
        proof: await forge(keyStore, {
          header: { typ: 'dpop+jwt', alg: 'HS256', jwk: await keyStore.publicJwk() },
        }),
      };
    },

    missing_jwk: async () => {
      const { keyStore, input } = await baseline();
      return {
        ...input,
        proof: await forge(keyStore, { header: { typ: 'dpop+jwt', alg: 'ES256' } }),
      };
    },

    // The key-confusion guard: a proof must never carry a private component.
    private_key_in_jwk: async () => {
      const { keyStore, input } = await baseline();
      return {
        ...input,
        proof: await forge(keyStore, {
          header: {
            typ: 'dpop+jwt',
            alg: 'ES256',
            jwk: { ...(await keyStore.publicJwk()), d: 'not-a-real-private-scalar' },
          },
        }),
      };
    },

    malformed_jwk: async () => {
      const { keyStore, input } = await baseline();
      const jwk = (await keyStore.publicJwk()) as Record<string, unknown>;
      const withoutY = Object.fromEntries(Object.entries(jwk).filter(([member]) => member !== 'y'));
      return {
        ...input,
        proof: await forge(keyStore, {
          header: { typ: 'dpop+jwt', alg: 'ES256', jwk: withoutY },
        }),
      };
    },

    // The stored credential key is not one this package can express as a JWK.
    unsupported_credential_key: async () => ({
      ...(await baseline()).input,
      publicKeyCose: Uint8Array.of(0),
    }),

    key_mismatch: async () => {
      const { input } = await baseline();
      const stranger = await generateKeyStore(ES256);
      return { ...input, publicKeyCose: await stranger.keyStore.publicKeyCose() };
    },

    malformed_signature: async () => {
      const { input } = await baseline();
      const [header, payload] = input.proof.split('.');
      return { ...input, proof: `${header}.${payload}.not!base64url` };
    },

    bad_signature: async () => {
      const { keyStore, input } = await baseline();
      const [header, payload] = input.proof.split('.');
      // Correct key, correct shape, signed over something else entirely.
      const wrong = await keyStore.signJws(utf8('a different message'));
      return { ...input, proof: `${header}.${payload}.${encodeBase64Url(wrong)}` };
    },

    malformed_payload: async () => {
      const { keyStore, input } = await baseline();
      return { ...input, proof: await forge(keyStore, { rawPayload: 'bm90LWpzb24' }) };
    },

    bad_jti: async () => {
      const { keyStore, input } = await baseline();
      return {
        ...input,
        proof: await forge(keyStore, {
          payload: { jti: 'short', htm: 'POST', htu: URL_UNDER_TEST, iat: 0, ath: '' },
        }),
      };
    },

    htm_mismatch: async () => ({ ...(await baseline()).input, method: 'GET' }),

    htu_mismatch: async () => ({
      ...(await baseline()).input,
      url: 'https://app.example.test/api/other',
    }),

    bad_iat: async () => {
      const { keyStore, input } = await baseline();
      return {
        ...input,
        proof: await forge(keyStore, {
          payload: { jti: 'a'.repeat(16), htm: 'POST', htu: URL_UNDER_TEST, iat: 'soon', ath: '' },
        }),
      };
    },

    iat_out_of_window: async () => ({
      ...(await baseline()).input,
      now: Date.now() + 10 * 60_000,
    }),

    ath_mismatch: async () => ({ ...(await baseline()).input, accessToken: 'a-different-token' }),

    use_dpop_nonce: async () => ({ ...(await baseline()).input, nonces: ['expected-nonce'] }),
  };

  for (const [reason, build] of Object.entries(cases)) {
    it(`rejects ${reason}`, async () => {
      expect(await verifyDpopProof(await build())).toEqual({ valid: false, reason });
    });
  }

  it('covers every reason the module can return', async () => {
    // Guards against a reason being added without a case, which would otherwise
    // leave a rejection path silently untested again.
    const source = await import('node:fs/promises').then((fs) =>
      fs.readFile(new URL('../../packages/server/src/dpop.ts', import.meta.url), 'utf8'),
    );
    const declared = new Set([...source.matchAll(/invalid\('([a-z_]+)'\)/gu)].map((m) => m[1]));
    expect([...declared].sort()).toEqual(Object.keys(cases).sort());
  });
});

describe('rejections that share a reason', () => {
  // These reach different guards behind the same reason string, so they belong
  // here rather than in the table above, which is keyed one case per reason.

  it('rejects a header segment that is not base64url at all', async () => {
    const { input } = await baseline();
    const [, payload, signature] = input.proof.split('.');
    // The table's `malformed_header` case decodes cleanly and fails to parse as
    // JSON; this one fails to decode.
    await expect(
      verifyDpopProof({ ...input, proof: `not!base64url.${payload}.${signature}` }),
    ).resolves.toEqual({ valid: false, reason: 'malformed_header' });
  });

  it('rejects a jwk missing its curve', async () => {
    const { keyStore, input } = await baseline();
    const proof = await forge(keyStore, {
      header: { typ: 'dpop+jwt', alg: 'ES256', jwk: { kty: 'EC', x: 'a', y: 'b' } },
    });
    await expect(verifyDpopProof({ ...input, proof })).resolves.toEqual({
      valid: false,
      reason: 'malformed_jwk',
    });
  });

  it('rejects an OKP credential key on the wrong curve or with a short point', async () => {
    const { encodeCborMap } = await import('../../packages/client/src/cbor.js');
    const okp = (crv: number, length: number) =>
      encodeCborMap(
        new Map<number, number | Uint8Array>([
          [1, 1],
          [3, -8],
          [-1, crv],
          [-2, new Uint8Array(length)],
        ]),
      );
    expect(coseToJwk(okp(4, 32))).toBeNull();
    expect(coseToJwk(okp(6, 31))).toBeNull();
    expect(coseToJwk(okp(6, 32))).toMatchObject({ kty: 'OKP', crv: 'Ed25519' });
  });
});

describe('accepted nonces', () => {
  it('accepts a proof carrying any nonce in the set', async () => {
    const { keyStore } = await generateKeyStore(ES256);
    const proof = await createDpopProof({
      keyStore,
      method: 'POST',
      url: URL_UNDER_TEST,
      accessToken: TOKEN,
      nonce: 'previous-slot',
    });
    // Current and previous slot are both offered, which is what stops a rotation
    // landing mid-flight from rejecting a proof built moments earlier.
    await expect(
      verifyDpopProof({
        proof,
        method: 'POST',
        url: URL_UNDER_TEST,
        accessToken: TOKEN,
        publicKeyCose: await keyStore.publicKeyCose(),
        nonces: ['current-slot', 'previous-slot'],
      }),
    ).resolves.toMatchObject({ valid: true });
  });
});

describe('coseToJwk', () => {
  it('maps an EC2 P-256 key', async () => {
    const { keyStore } = await generateKeyStore(ES256);
    const jwk = coseToJwk(await keyStore.publicKeyCose());
    expect(jwk).toMatchObject({ kty: 'EC', crv: 'P-256' });
    // Round-trips to the same thumbprint the client computes from its own JWK.
    if (!jwk) {
      throw new Error('an EC2 COSE key should map to a JWK');
    }
    expect(await jwkThumbprint(jwk)).toBe(
      await jwkThumbprint((await keyStore.publicJwk()) as never),
    );
  });

  it('maps an OKP Ed25519 key', async () => {
    const { keyStore } = await generateKeyStore(EDDSA);
    expect(coseToJwk(await keyStore.publicKeyCose())).toMatchObject({
      kty: 'OKP',
      crv: 'Ed25519',
    });
  });

  it('returns null for bytes that are not a COSE key', () => {
    expect(coseToJwk(Uint8Array.of(0))).toBeNull();
    expect(coseToJwk(new Uint8Array(0))).toBeNull();
  });

  it('returns null for a COSE key this package cannot use', async () => {
    const { encodeCborMap } = await import('../../packages/client/src/cbor.js');
    // EC2 on an unsupported curve, and a truncated coordinate on P-256.
    const wrongCurve = encodeCborMap(
      new Map<number, number | Uint8Array>([
        [1, 2],
        [3, -7],
        [-1, 2],
        [-2, new Uint8Array(32)],
        [-3, new Uint8Array(32)],
      ]),
    );
    expect(coseToJwk(wrongCurve)).toBeNull();

    const shortCoordinate = encodeCborMap(
      new Map<number, number | Uint8Array>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, new Uint8Array(31)],
        [-3, new Uint8Array(32)],
      ]),
    );
    expect(coseToJwk(shortCoordinate)).toBeNull();
  });
});
