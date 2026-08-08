/**
 * Key custody.
 *
 * Nothing in this package assumes the private key is in memory. Everything a
 * credential needs from its key is behind {@link MachineKeyStore}, so a TPM, a
 * Secure Enclave, a PKCS#11 token or a cloud KMS can be dropped in behind the
 * same four members.
 *
 * Only the WebCrypto backend ships here, because it is the only one portable to
 * both a browser and a server runtime. The rest need platform bindings and
 * belong in host code — see `docs/API-AUTH.org`, /Key Custody/, for the
 * `keystore:` URI scheme and each backend's limits.
 *
 * Two of those limits are worth knowing before choosing: every non-exportable
 * backend is ES256-only, and Secure Enclave and TPM keys cannot be *imported* at
 * all — they are generated in place, so a key minted in a browser page can never
 * reach them.
 */

import { decodeBase64, decodeBase64Url, encodeBase64, owned } from './bytes.js';
import { type CborMap, encodeCborMap } from './cbor.js';
import { rawSignatureToDer } from './ecdsa.js';

/** COSE algorithm identifiers this package supports. */
export type CoseAlgorithm = -7 | -8;

/** ECDSA P-256 with SHA-256. The only algorithm hardware backends offer. */
export const ES256 = -7 as const satisfies CoseAlgorithm;
/** Ed25519. Avoids the DER/raw signature split, but software-only in practice. */
export const EDDSA = -8 as const satisfies CoseAlgorithm;

export type MachineKeyStore = {
  readonly algorithm: CoseAlgorithm;
  /** COSE_Key encoding of the public half, for registration. */
  publicKeyCose(): Promise<Uint8Array>;
  /** Public JWK, for the `jwk` header of a DPoP proof. */
  publicJwk(): Promise<JsonWebKey>;
  /** WebAuthn-shaped signature: DER for ES256, raw for EdDSA. */
  signWebAuthn(data: Uint8Array): Promise<Uint8Array>;
  /** JWS-shaped signature: raw `r ‖ s` for ES256, raw for EdDSA. */
  signJws(data: Uint8Array): Promise<Uint8Array>;
};

type ImportParameters = { name: 'ECDSA'; namedCurve: 'P-256' } | { name: 'Ed25519' };

function importParameters(algorithm: CoseAlgorithm): ImportParameters {
  return algorithm === ES256 ? { name: 'ECDSA', namedCurve: 'P-256' } : { name: 'Ed25519' };
}

function signParameters(algorithm: CoseAlgorithm): EcdsaParams | AlgorithmIdentifier {
  return algorithm === ES256 ? { name: 'ECDSA', hash: 'SHA-256' } : { name: 'Ed25519' };
}

/** Only the public members, so a private component can never leak into a proof header. */
function publicMembers(jwk: JsonWebKey): JsonWebKey {
  return jwk.kty === 'EC'
    ? { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y }
    : { kty: 'OKP', crv: jwk.crv, x: jwk.x };
}

/**
 * COSE_Key for a public JWK.
 *
 * Labels are inserted in canonical CBOR order (`1`, `3`, `-1`, `-2`, `-3`), so
 * the encoder's insertion-order output is already canonical.
 */
function coseFromJwk(jwk: JsonWebKey, algorithm: CoseAlgorithm): CborMap {
  const entries: CborMap = new Map();
  if (algorithm === ES256) {
    if (!jwk.x || !jwk.y) {
      throw new TypeError('An EC public JWK must have x and y.');
    }
    entries.set(1, 2); // kty: EC2
    entries.set(3, -7); // alg: ES256
    entries.set(-1, 1); // crv: P-256
    entries.set(-2, decodeBase64Url(jwk.x));
    entries.set(-3, decodeBase64Url(jwk.y));
    return entries;
  }
  if (!jwk.x) {
    throw new TypeError('An OKP public JWK must have x.');
  }
  entries.set(1, 1); // kty: OKP
  entries.set(3, -8); // alg: EdDSA
  entries.set(-1, 6); // crv: Ed25519
  entries.set(-2, decodeBase64Url(jwk.x));
  return entries;
}

class WebCryptoKeyStore implements MachineKeyStore {
  readonly algorithm: CoseAlgorithm;
  readonly #privateKey: CryptoKey;
  readonly #publicJwk: JsonWebKey;

  constructor(algorithm: CoseAlgorithm, privateKey: CryptoKey, publicJwk: JsonWebKey) {
    this.algorithm = algorithm;
    this.#privateKey = privateKey;
    this.#publicJwk = publicMembers(publicJwk);
  }

  async publicKeyCose(): Promise<Uint8Array> {
    return encodeCborMap(coseFromJwk(this.#publicJwk, this.algorithm));
  }

  async publicJwk(): Promise<JsonWebKey> {
    return { ...this.#publicJwk };
  }

  async signJws(data: Uint8Array): Promise<Uint8Array> {
    const signature = await globalThis.crypto.subtle.sign(
      signParameters(this.algorithm),
      this.#privateKey,
      owned(data),
    );
    return new Uint8Array(signature);
  }

  async signWebAuthn(data: Uint8Array): Promise<Uint8Array> {
    const raw = await this.signJws(data);
    return this.algorithm === ES256 ? rawSignatureToDer(raw) : raw;
  }
}

/**
 * Generate a fresh key pair.
 *
 * `exportPrivateKey` is what the provisioning page calls to render the one-time
 * `.env` line; it throws when the key was generated non-extractable.
 */
export async function generateKeyStore(
  algorithm: CoseAlgorithm = ES256,
  extractable = true,
): Promise<{ keyStore: MachineKeyStore; exportPrivateKey: () => Promise<string> }> {
  const pair = (await globalThis.crypto.subtle.generateKey(
    importParameters(algorithm),
    extractable,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  const publicJwk = await globalThis.crypto.subtle.exportKey('jwk', pair.publicKey);
  return {
    keyStore: new WebCryptoKeyStore(algorithm, pair.privateKey, publicJwk),
    exportPrivateKey: async () => {
      const pkcs8 = await globalThis.crypto.subtle.exportKey('pkcs8', pair.privateKey);
      return encodeBase64(new Uint8Array(pkcs8));
    },
  };
}

/**
 * Open a key store over a base64 PKCS#8 private key.
 *
 * The key is imported twice: once extractable, only to read the public members
 * out of its JWK — WebCrypto offers no way to derive a public key from a private
 * `CryptoKey` — and once non-extractable, which is the handle that actually
 * signs. So a process that read the key from a file cannot later be induced to
 * hand it back out through the signing handle.
 */
export async function importKeyStore(
  privateKeyBase64: string,
  algorithm: CoseAlgorithm = ES256,
): Promise<MachineKeyStore> {
  const pkcs8 = decodeBase64(privateKeyBase64);
  const parameters = importParameters(algorithm);
  const readable = await globalThis.crypto.subtle.importKey(
    'pkcs8',
    owned(pkcs8),
    parameters,
    true,
    ['sign'],
  );
  const jwk = await globalThis.crypto.subtle.exportKey('jwk', readable);
  const signingKey = await globalThis.crypto.subtle.importKey(
    'pkcs8',
    owned(pkcs8),
    parameters,
    false,
    ['sign'],
  );
  return new WebCryptoKeyStore(algorithm, signingKey, jwk);
}
