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

/** Keystore schemes this format admits. Anything else is refused at parse time. */
const KEYSTORE_SCHEMES = ['file', 'keychain', 'dpapi', 'keyring', 'tpm', 'kms', 'agent'];

/** A `keystore:` URI instead of inline key material. */
export function isKeystoreReference(value: string): boolean {
  return value.startsWith('keystore:');
}

/**
 * Wrap a value in POSIX single quotes, so a file that is `source`d cannot execute
 * any of it.
 *
 * Inline base64 key material happens to be shell-safe, but `keystore:` URIs are
 * caller-supplied and need not be: a backend path containing a space, a quote, `$(…)`
 * or a newline would otherwise be interpreted rather than read. Single quotes suspend
 * every shell expansion, and the one character they cannot contain — an apostrophe —
 * is emitted as `'\''`, the standard idiom for ending the quoted run, escaping a
 * literal apostrophe, and starting a new run.
 */
function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
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
  // A newline in the key would end the assignment and turn the remainder into
  // whatever the shell makes of it; a NUL or escape would corrupt the file quietly.
  // eslint-disable-next-line no-control-regex -- detecting control characters is the point
  if (/[\u0000-\u001f\u007f]/u.test(key)) {
    throw new Error('The credential key must not contain control characters.');
  }
  const lines = comment ? [`# ${comment.replaceAll(/[\r\n]+/gu, ' ')}`] : [];
  lines.push(`${CREDENTIAL_VARIABLE}='${json}'`, `${CREDENTIAL_KEY_VARIABLE}=${shellQuote(key)}`);
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

/**
 * The largest credential file this will read.
 *
 * A real one is well under a kilobyte. The bound exists so a wrong path — a log, a
 * database dump, a video — fails immediately instead of being parsed line by line.
 */
const MAX_FILE_BYTES = 64 * 1024;

/**
 * Read the two variables out of `.env` text, ignoring comments and other keys.
 *
 * Refuses a file larger than {@link MAX_FILE_BYTES}, and refuses either variable
 * appearing twice: with two assignments a shell would take the last and a careless
 * reader the first, so "which key is this?" would have two answers.
 */
export function parseCredentialFile(text: string): { payload: string; key: string } | null {
  if (text.length > MAX_FILE_BYTES) {
    throw new Error(`The credential file is larger than ${String(MAX_FILE_BYTES)} bytes.`);
  }
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
      if (payload !== undefined) {
        throw new Error(`${CREDENTIAL_VARIABLE} is assigned more than once.`);
      }
      payload = value;
    } else if (name === CREDENTIAL_KEY_VARIABLE) {
      if (key !== undefined) {
        throw new Error(`${CREDENTIAL_KEY_VARIABLE} is assigned more than once.`);
      }
      key = value;
    }
  }
  // eslint-disable-next-line no-control-regex -- detecting control characters is the point
  if (key !== undefined && /[\u0000-\u001f\u007f]/u.test(key)) {
    throw new Error('The credential key must not contain control characters.');
  }
  if (key !== undefined && isKeystoreReference(key)) {
    const matched = /^keystore:(?<scheme>[a-z0-9+.-]+)/iu.exec(key);
    const scheme = matched?.groups?.scheme.toLowerCase();
    if (scheme === undefined || !KEYSTORE_SCHEMES.includes(scheme)) {
      throw new Error(
        `Unsupported keystore scheme in ${CREDENTIAL_KEY_VARIABLE}; expected one of ${KEYSTORE_SCHEMES.join(', ')}.`,
      );
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

  const payload = candidate as unknown as CredentialPayload;
  const baseUrl = requireHttpsOrigin(payload.baseUrl, 'baseUrl');
  const origin = requireHttpsOrigin(payload.origin, 'origin');

  // WebAuthn binds a credential to an RP ID, and the browser only signs for an
  // origin at or beneath it. A file whose origin does not satisfy that relationship
  // describes a ceremony no server will accept, so say so here rather than let the
  // signature be rejected with no explanation.
  if (origin.hostname !== payload.rpId && !origin.hostname.endsWith(`.${payload.rpId}`)) {
    throw new Error(
      `LWA_CREDENTIAL origin ${origin.origin} is not at or beneath rpId ${payload.rpId}.`,
    );
  }
  // The script sends its requests to baseUrl and claims `origin` in clientDataJSON.
  // Two different hosts means one of the two is wrong.
  if (baseUrl.hostname !== origin.hostname) {
    throw new Error(
      `LWA_CREDENTIAL baseUrl host ${baseUrl.hostname} does not match origin host ${origin.hostname}.`,
    );
  }
  requireBase64Url(payload.credentialId, 'credentialId');
  requireBase64Url(payload.userHandle, 'userHandle');
  // A 32-byte handle is what `createUserHandle()` produces and what the server
  // requires; anything else would fail the ceremony later, for no visible reason.
  if (decodedLength(payload.userHandle) !== 32) {
    throw new Error('LWA_CREDENTIAL userHandle must be 32 bytes.');
  }
  return payload;
}

/**
 * Parse a URL, require HTTPS, and reject the shapes that make an origin ambiguous.
 *
 * Loopback over plain HTTP is allowed because that is the one place browsers run
 * WebAuthn without TLS, and the demo needs it. Everything else must be HTTPS: a
 * machine credential authenticates over the network, and its assertions and DPoP
 * proofs are only as private as the transport.
 *
 * Userinfo is refused because `https://evil.test@app.example.com/` reads as one host
 * to a person and another to a parser. A path, query or fragment is refused because
 * an origin has none, and silently discarding one hides a misconfiguration.
 */
function requireHttpsOrigin(value: string, field: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`LWA_CREDENTIAL ${field} is not a URL: ${value}`);
  }
  const loopback =
    url.hostname === 'localhost' ||
    url.hostname.endsWith('.localhost') ||
    url.hostname === '127.0.0.1' ||
    url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new Error(
      `LWA_CREDENTIAL ${field} must be HTTPS (or loopback HTTP for development): ${value}`,
    );
  }
  if (url.username || url.password) {
    throw new Error(`LWA_CREDENTIAL ${field} must not contain userinfo: ${value}`);
  }
  if (url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) {
    throw new Error(`LWA_CREDENTIAL ${field} must be a bare origin: ${value}`);
  }
  return url;
}

/** Unpadded base64url only, so a value round-trips to the same bytes everywhere. */
function requireBase64Url(value: string, field: string): void {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new Error(`LWA_CREDENTIAL ${field} is not unpadded base64url.`);
  }
}

function decodedLength(base64Url: string): number {
  // Four base64 characters carry three bytes; a trailing group of 2 or 3 carries 1 or 2.
  const remainder = base64Url.length % 4;
  return Math.floor(base64Url.length / 4) * 3 + (remainder === 0 ? 0 : remainder - 1);
}
