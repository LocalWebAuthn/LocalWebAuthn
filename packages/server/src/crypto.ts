const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

export function defaultRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

export async function sha256(value: string | Uint8Array): Promise<Uint8Array> {
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  const ownedBytes = Uint8Array.from(bytes);
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', ownedBytes.buffer));
}

export function encodeBase32(bytes: Uint8Array): string {
  let bits = 0;
  let accumulator = 0;
  let output = '';

  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      bits -= 5;
      output += BASE32_ALPHABET[(accumulator >>> bits) & 31];
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(accumulator << (5 - bits)) & 31];
  }

  return output;
}

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

export function decodeBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) {
    return null;
  }

  try {
    const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
    const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
    const binary = atob(normalized + padding);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }

  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

export function createUserHandle(randomBytes = defaultRandomBytes): Uint8Array {
  return randomBytes(32);
}

export function createEnrollmentToken(randomBytes = defaultRandomBytes): string {
  return encodeBase32(randomBytes(32));
}

export function createOpaqueToken(randomBytes = defaultRandomBytes): string {
  return encodeBase64Url(randomBytes(32));
}
