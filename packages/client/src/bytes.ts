/**
 * Byte and base64 helpers.
 *
 * Deliberately duplicated rather than imported from `@localwebauthn/server`: a
 * client that talks to a LocalWebAuthn server must not have to install the
 * server, and this file has no dependencies at all.
 */

export function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function toBinary(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return binary;
}

export function encodeBase64(bytes: Uint8Array): string {
  return btoa(toBinary(bytes));
}

export function decodeBase64(value: string): Uint8Array {
  const binary = atob(value.replaceAll(/\s+/gu, ''));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function encodeBase64Url(bytes: Uint8Array): string {
  return encodeBase64(bytes).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

export function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  return decodeBase64(normalized + '='.repeat((4 - (normalized.length % 4)) % 4));
}

/**
 * Copy into a fresh `ArrayBuffer`-backed view.
 *
 * WebCrypto's `BufferSource` excludes `SharedArrayBuffer`, which a plain
 * `Uint8Array` parameter cannot rule out, so every value handed to `subtle` goes
 * through here.
 */
export function owned(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy;
}

export async function sha256(value: Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof value === 'string' ? utf8(value) : value;
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', owned(bytes)));
}

export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}
