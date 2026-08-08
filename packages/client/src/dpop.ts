/**
 * DPoP proof construction (RFC 9449).
 *
 * The proof is signed by the *same* key as the WebAuthn assertion, so the server
 * derives the expected thumbprint from the credential it already stores and keeps
 * no per-session key material. Safe because the two signed inputs cannot collide:
 * a JWS signing input is printable ASCII beginning `eyJ`, while a WebAuthn
 * assertion covers 69 bytes opening with a SHA-256 digest.
 *
 * Note that this signature is the *raw* `r ‖ s` form, not the DER the same key
 * emits for an assertion — see `ecdsa.ts`.
 */

import { encodeBase64Url, randomBytes, sha256, utf8 } from './bytes.js';
import { type CoseAlgorithm, ES256, type MachineKeyStore } from './keystore.js';

function jwsAlgorithm(algorithm: CoseAlgorithm): 'ES256' | 'EdDSA' {
  return algorithm === ES256 ? 'ES256' : 'EdDSA';
}

/** Target URI per RFC 9449: scheme, host, port and path — no query, no fragment. */
function targetUri(url: string): string {
  const parsed = new URL(url);
  return `${parsed.origin}${parsed.pathname}`;
}

export async function createDpopProof(input: {
  keyStore: MachineKeyStore;
  method: string;
  url: string;
  /** The session token this proof accompanies; hashed into `ath`. */
  accessToken: string;
  /** Most recent `DPoP-Nonce` from the server, when it demands one. */
  nonce?: string;
  now?: () => number;
}): Promise<string> {
  const header = {
    typ: 'dpop+jwt',
    alg: jwsAlgorithm(input.keyStore.algorithm),
    jwk: await input.keyStore.publicJwk(),
  };
  const payload: Record<string, unknown> = {
    jti: encodeBase64Url(randomBytes(16)),
    htm: input.method.toUpperCase(),
    htu: targetUri(input.url),
    iat: Math.floor((input.now?.() ?? Date.now()) / 1000),
    ath: encodeBase64Url(await sha256(input.accessToken)),
  };
  if (input.nonce !== undefined) {
    payload.nonce = input.nonce;
  }

  const signingInput = `${encodeBase64Url(utf8(JSON.stringify(header)))}.${encodeBase64Url(
    utf8(JSON.stringify(payload)),
  )}`;
  const signature = await input.keyStore.signJws(utf8(signingInput));
  return `${signingInput}.${encodeBase64Url(signature)}`;
}
