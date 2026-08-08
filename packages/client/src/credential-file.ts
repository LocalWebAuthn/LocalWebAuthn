/**
 * The two-line `.env` credential format.
 *
 * ```conf
 * # nightly-export -- created 2026-08-08
 * LWA_CREDENTIAL='{"v":1,"baseUrl":"https://app.example.com",...}'
 * LWA_CREDENTIAL_KEY=MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...
 * ```
 *
 * One secret, several public values. Everything in `LWA_CREDENTIAL` is safe in a
 * log or a support ticket; only the key line matters.
 *
 * **The single quotes are load-bearing.** Without them `source .env` lets the
 * shell strip the JSON's double quotes. With them, no field value may contain an
 * apostrophe — which is why the human-authored label lives in a comment rather
 * than in the payload. Every field below is a base64url string, a URL, a
 * hostname, or a number, so the constraint holds by construction; keep it that
 * way when adding fields, and emit compact JSON so the value stays on one line.
 */

import type { CoseAlgorithm } from './keystore.js';

/** Current payload schema version. */
export const CREDENTIAL_PAYLOAD_VERSION = 1;

export type CredentialPayload = {
  v: number;
  baseUrl: string;
  rpId: string;
  origin: string;
  /** base64url, 32 bytes. */
  credentialId: string;
  /** base64url, 32 bytes. */
  userHandle: string;
  alg: CoseAlgorithm;
};

export const CREDENTIAL_VARIABLE = 'LWA_CREDENTIAL';
export const CREDENTIAL_KEY_VARIABLE = 'LWA_CREDENTIAL_KEY';

/** A `keystore:` URI instead of inline key material. */
export function isKeystoreReference(value: string): boolean {
  return value.startsWith('keystore:');
}

/**
 * Render the file.
 *
 * @param key - Base64 PKCS#8, or a `keystore:` URI.
 * @param comment - Free text for the leading comment; newlines are stripped.
 */
export function formatCredentialFile(
  payload: CredentialPayload,
  key: string,
  comment?: string,
): string {
  const json = JSON.stringify(payload);
  if (json.includes("'")) {
    // Would break the single-quoting the format depends on. Fail loudly rather
    // than emit a file that breaks only under `source`.
    throw new Error('Credential payload fields must not contain an apostrophe.');
  }
  const lines = comment ? [`# ${comment.replaceAll(/[\r\n]+/gu, ' ')}`] : [];
  lines.push(`${CREDENTIAL_VARIABLE}='${json}'`, `${CREDENTIAL_KEY_VARIABLE}=${key}`);
  return `${lines.join('\n')}\n`;
}

function unquote(value: string): string {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
    (trimmed.startsWith('"') && trimmed.endsWith('"'))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

/** Read the two variables out of `.env` text, ignoring comments and other keys. */
export function parseCredentialFile(text: string): { payload: string; key: string } | null {
  let payload: string | undefined;
  let key: string | undefined;
  for (const line of text.split(/\r?\n/u)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    const separator = trimmed.indexOf('=');
    if (separator <= 0) {
      continue;
    }
    const name = trimmed
      .slice(0, separator)
      .trim()
      .replace(/^export\s+/u, '');
    const value = unquote(trimmed.slice(separator + 1));
    if (name === CREDENTIAL_VARIABLE) {
      payload = value;
    } else if (name === CREDENTIAL_KEY_VARIABLE) {
      key = value;
    }
  }
  return payload !== undefined && key !== undefined ? { payload, key } : null;
}

/**
 * Validate a payload and refuse an unknown version.
 *
 * Refusing rather than ignoring an unrecognised `v` is deliberate: a later
 * version could add a load-bearing field — an audience, say — and a client that
 * guessed would authenticate against the wrong thing.
 */
export function parseCredentialPayload(json: string): CredentialPayload {
  const parsed: unknown = JSON.parse(json);
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('LWA_CREDENTIAL is not a JSON object.');
  }
  const candidate = parsed as Record<string, unknown>;
  if (candidate.v !== CREDENTIAL_PAYLOAD_VERSION) {
    throw new Error(
      `Unsupported LWA_CREDENTIAL version ${String(candidate.v)}; this client understands ${String(
        CREDENTIAL_PAYLOAD_VERSION,
      )}.`,
    );
  }
  for (const field of ['baseUrl', 'rpId', 'origin', 'credentialId', 'userHandle'] as const) {
    if (typeof candidate[field] !== 'string' || !candidate[field]) {
      throw new Error(`LWA_CREDENTIAL is missing ${field}.`);
    }
  }
  if (candidate.alg !== -7 && candidate.alg !== -8) {
    throw new Error(`Unsupported LWA_CREDENTIAL alg ${String(candidate.alg)}.`);
  }
  return candidate as CredentialPayload;
}
