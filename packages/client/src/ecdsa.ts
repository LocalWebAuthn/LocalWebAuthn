/**
 * ECDSA signature re-encoding.
 *
 * One key signs in two incompatible formats, and mixing them up produces a
 * verification failure with no diagnostic:
 *
 * | Context            | Standard         | Encoding                        |
 * | ------------------ | ---------------- | ------------------------------- |
 * | WebAuthn assertion | COSE alg `-7`    | ASN.1 DER `SEQUENCE { r, s }`   |
 * | DPoP proof (JWS)   | RFC 7518 `ES256` | raw `r ‖ s`, 64 bytes           |
 *
 * WebCrypto's `ECDSA` sign returns the raw form, so the WebAuthn path converts
 * and the DPoP path does not. Ed25519 sidesteps this entirely — raw 64 bytes in
 * both — which is a decent reason to prefer it where the key store allows.
 */

import { concat } from './bytes.js';

/** Strip leading zeros, then re-add one if the high bit would read as negative. */
function derInteger(value: Uint8Array): Uint8Array {
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) {
    start += 1;
  }
  const trimmed = value.subarray(start);
  const body = (trimmed[0] & 0x80) === 0 ? trimmed : concat(Uint8Array.of(0), trimmed);
  return concat(Uint8Array.of(0x02, body.length), body);
}

/**
 * Convert a raw P-256 `r ‖ s` signature to ASN.1 DER.
 *
 * @param raw - Exactly 64 bytes, as WebCrypto's ECDSA sign returns for P-256.
 */
export function rawSignatureToDer(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) {
    throw new TypeError(`Expected a 64-byte P-256 signature, received ${String(raw.length)}.`);
  }
  const body = concat(derInteger(raw.subarray(0, 32)), derInteger(raw.subarray(32, 64)));
  return concat(Uint8Array.of(0x30, body.length), body);
}
