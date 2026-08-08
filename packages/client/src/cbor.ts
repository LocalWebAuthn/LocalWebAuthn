/**
 * The sliver of CBOR (RFC 8949) that WebAuthn registration needs.
 *
 * Two structures, and nothing else: a COSE_Key map with small integer labels,
 * and the `fmt: "none"` attestation object. That is a handful of major types —
 * unsigned and negative integers, byte strings, text strings, and maps — so a
 * full CBOR implementation would be dead weight and another dependency to audit.
 *
 * Encoding only. Nothing here parses CBOR; the server side does that with
 * `@simplewebauthn/server`'s decoder.
 */

import { concat, utf8 } from './bytes.js';

const MAJOR_UNSIGNED = 0;
const MAJOR_NEGATIVE = 1;
const MAJOR_BYTES = 2;
const MAJOR_TEXT = 3;
const MAJOR_MAP = 5;

/**
 * The initial byte plus any following length bytes.
 *
 * Values below 24 pack into the initial byte; larger ones use a 1-, 2- or 4-byte
 * follower. WebAuthn never needs the 8-byte form — the longest thing encoded
 * here is a public key — so it is omitted rather than written untested.
 */
function head(major: number, value: number): Uint8Array {
  if (value < 24) {
    return Uint8Array.of((major << 5) | value);
  }
  if (value < 0x100) {
    return Uint8Array.of((major << 5) | 24, value);
  }
  if (value < 0x10000) {
    return Uint8Array.of((major << 5) | 25, value >> 8, value & 0xff);
  }
  if (value <= 0xffffffff) {
    return Uint8Array.of(
      (major << 5) | 26,
      (value >>> 24) & 0xff,
      (value >>> 16) & 0xff,
      (value >>> 8) & 0xff,
      value & 0xff,
    );
  }
  throw new RangeError('CBOR value too large for this encoder.');
}

/** A negative integer `-n` is encoded as major type 1 carrying `n - 1`. */
function integer(value: number): Uint8Array {
  if (!Number.isInteger(value)) {
    throw new TypeError('CBOR integers must be integers.');
  }
  return value < 0 ? head(MAJOR_NEGATIVE, -value - 1) : head(MAJOR_UNSIGNED, value);
}

function byteString(value: Uint8Array): Uint8Array {
  return concat(head(MAJOR_BYTES, value.length), value);
}

function textString(value: string): Uint8Array {
  const bytes = utf8(value);
  return concat(head(MAJOR_TEXT, bytes.length), bytes);
}

export type CborValue = number | string | Uint8Array | CborMap;
export type CborMap = Map<number | string, CborValue>;

function encodeValue(value: CborValue): Uint8Array {
  if (typeof value === 'number') {
    return integer(value);
  }
  if (typeof value === 'string') {
    return textString(value);
  }
  if (value instanceof Uint8Array) {
    return byteString(value);
  }
  return encodeCborMap(value);
}

/**
 * Encode a map, preserving insertion order.
 *
 * Insertion order rather than canonical (length-then-bytewise) ordering, because
 * the two structures this encodes are built here with their keys already in
 * canonical order, and a decoder is required to accept any order regardless.
 * Callers relying on canonical output must insert accordingly.
 */
export function encodeCborMap(entries: CborMap): Uint8Array {
  const parts = [head(MAJOR_MAP, entries.size)];
  for (const [key, value] of entries) {
    parts.push(typeof key === 'number' ? integer(key) : textString(key));
    parts.push(encodeValue(value));
  }
  return concat(...parts);
}
