/**
 * DPoP (RFC 9449) proof verification, bound to a stored WebAuthn credential.
 *
 * The usual OAuth deployment stores a `jkt` — the thumbprint of the key that
 * will sign proofs — alongside each access token, because there the DPoP key is
 * unrelated to whatever authenticated the client. Here it *is* the credential
 * key: a software client signs its WebAuthn assertion and its DPoP proofs with
 * one key, so the expected thumbprint is derived from `credentials.public_key`
 * and there is nothing new to store per session.
 *
 * The per-request check therefore reduces to: this proof was signed by the same
 * key that produced the assertion that opened this session.
 *
 * Reusing one key across the two protocols is safe because the signed inputs
 * cannot collide. A WebAuthn assertion covers `authenticatorData ‖
 * SHA-256(clientDataJSON)` — 69 bytes opening with a SHA-256 digest — while a
 * JWS signing input is printable ASCII that always begins `eyJ`. The separation
 * is structural, not a coincidence of encoding.
 */

import { cose, decodeCredentialPublicKey } from '@simplewebauthn/server/helpers';

import { decodeBase64Url, encodeBase64Url, equalBytes, sha256 } from './crypto.js';

/** JWS algorithms accepted in a proof header, matching the COSE algorithms this package registers. */
const SUPPORTED_ALGORITHMS = new Set(['ES256', 'EdDSA']);

/** Public JWK for an EC2 P-256 or OKP Ed25519 key. */
export type PublicJwk =
  { kty: 'EC'; crv: 'P-256'; x: string; y: string } | { kty: 'OKP'; crv: 'Ed25519'; x: string };

export type DpopVerificationInput = {
  /** Raw `DPoP` header value: a compact JWS. */
  proof: string;
  /** Request method, e.g. `"POST"`. */
  method: string;
  /** Full request URL; query and fragment are stripped before comparison. */
  url: string;
  /** The session token this proof accompanies, hashed into the `ath` claim. */
  accessToken: string;
  /** COSE public key of the credential that opened the session. */
  publicKeyCose: Uint8Array;
  /**
   * When non-empty, the proof's `nonce` must be one of these — normally the
   * current and previous rotation slot, so a rotation landing mid-flight does not
   * reject a proof built moments earlier.
   */
  nonces?: string[];
  /** Accepted clock skew for `iat`, in milliseconds. Defaults to 60s either way. */
  skewMs?: number;
  now?: number;
};

export type DpopVerification =
  | {
      valid: true;
      /** SHA-256 of the `jti`, for the single-use claim in the store. */
      jtiHash: Uint8Array;
      /** When the replay-cache entry may be reaped. */
      expiresAt: number;
    }
  | { valid: false; reason: string };

function invalid(reason: string): DpopVerification {
  return { valid: false, reason };
}

/**
 * Convert a COSE public key to its public JWK form.
 *
 * Returns `null` for key types this package does not register (RSA), or for a
 * structurally incomplete key.
 */
export function coseToJwk(publicKeyCose: Uint8Array): PublicJwk | null {
  try {
    return decodeCoseToJwk(publicKeyCose);
  } catch {
    // The whole decode is guarded, not just the parse. `decodeCredentialPublicKey`
    // is *typed* as returning a Map but will happily hand back whatever the CBOR
    // decoded to — a bare integer, for instance — and the type guards below then
    // call `.get` on it and throw. A verifier that throws is a 500 where a
    // rejection was meant, so every path out of here returns `null` instead.
    return null;
  }
}

function decodeCoseToJwk(publicKeyCose: Uint8Array): PublicJwk | null {
  const decoded = decodeCredentialPublicKey(Uint8Array.from(publicKeyCose));
  // Deliberately not `instanceof Map`: that narrows the declared union down to the
  // Map intersection, after which SimpleWebAuthn's own type predicates narrow the
  // remaining branch to `never`. This checks the same thing without touching the
  // static type.
  if (typeof (decoded as { get?: unknown }).get !== 'function') {
    return null;
  }

  if (cose.isCOSEPublicKeyEC2(decoded)) {
    const crv = decoded.get(cose.COSEKEYS.crv);
    const x = decoded.get(cose.COSEKEYS.x);
    const y = decoded.get(cose.COSEKEYS.y);
    if (
      crv !== cose.COSECRV.P256 ||
      !(x instanceof Uint8Array) ||
      !(y instanceof Uint8Array) ||
      x.length !== 32 ||
      y.length !== 32
    ) {
      return null;
    }
    return { kty: 'EC', crv: 'P-256', x: encodeBase64Url(x), y: encodeBase64Url(y) };
  }
  if (cose.isCOSEPublicKeyOKP(decoded)) {
    const crv = decoded.get(cose.COSEKEYS.crv);
    const x = decoded.get(cose.COSEKEYS.x);
    if (crv !== cose.COSECRV.ED25519 || !(x instanceof Uint8Array) || x.length !== 32) {
      return null;
    }
    return { kty: 'OKP', crv: 'Ed25519', x: encodeBase64Url(x) };
  }
  return null;
}

/**
 * Whether a parsed header `jwk` has the members {@link jwkThumbprint} needs.
 *
 * Checked before hashing rather than after. `jwkThumbprint` interpolates its
 * members into a string and so cannot fail on any value `JSON.parse` can produce
 * — a jwk missing `y` would hash the literal text `"undefined"` and then merely
 * fail the comparison. That works by accident, and two differently-malformed jwks
 * can hash identically. Validating first makes the rejection deliberate, and gives
 * the failure its own reason instead of masquerading as `key_mismatch`.
 */
function isPublicJwk(value: unknown): value is PublicJwk {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const jwk = value as Record<string, unknown>;
  if (typeof jwk.crv !== 'string' || typeof jwk.x !== 'string') {
    return false;
  }
  if (jwk.kty === 'EC') {
    return typeof jwk.y === 'string';
  }
  return jwk.kty === 'OKP';
}

/**
 * RFC 7638 JWK thumbprint.
 *
 * The canonical form contains only the required members, in lexicographic order,
 * with no whitespace — so the JSON below is written by hand rather than by
 * `JSON.stringify` over an object whose key order would be incidental.
 */
export async function jwkThumbprint(jwk: PublicJwk): Promise<string> {
  const canonical =
    jwk.kty === 'EC'
      ? `{"crv":"${jwk.crv}","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`
      : `{"crv":"${jwk.crv}","kty":"OKP","x":"${jwk.x}"}`;
  return encodeBase64Url(await sha256(canonical));
}

function parseJsonSegment(segment: string): Record<string, unknown> | null {
  const bytes = decodeBase64Url(segment);
  if (!bytes) {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return typeof parsed === 'object' && parsed !== null
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** Target URI comparison per RFC 9449: scheme, host, port and path; no query or fragment. */
function normalizeTargetUri(value: string): string | null {
  try {
    const url = new URL(value);
    return `${url.origin}${url.pathname}`;
  } catch {
    return null;
  }
}

async function verifySignature(
  jwk: PublicJwk,
  algorithm: string,
  signingInput: string,
  signature: Uint8Array,
): Promise<boolean> {
  // ES256 JWS signatures are the raw r‖s concatenation (RFC 7518 3.4), which is
  // exactly what WebCrypto's ECDSA verify expects — unlike the DER encoding the
  // same key produces for a WebAuthn assertion.
  const parameters =
    algorithm === 'ES256'
      ? ({ name: 'ECDSA', namedCurve: 'P-256' } as const)
      : ({ name: 'Ed25519' } as const);
  const verifyParameters =
    algorithm === 'ES256'
      ? ({ name: 'ECDSA', hash: 'SHA-256' } as const)
      : ({ name: 'Ed25519' } as const);

  try {
    const key = await globalThis.crypto.subtle.importKey('jwk', jwk, parameters, false, ['verify']);
    return await globalThis.crypto.subtle.verify(
      verifyParameters,
      key,
      Uint8Array.from(signature),
      new TextEncoder().encode(signingInput),
    );
  } catch {
    return false;
  }
}

/**
 * Verify a DPoP proof against the credential that opened the session.
 *
 * Checks, in order: the compact JWS shape; `typ` and `alg`; that the embedded
 * `jwk` is the credential's own key, by thumbprint; the signature; then `htm`,
 * `htu`, `iat`, `ath` and `nonce`.
 *
 * A `true` result still requires the caller to claim `jtiHash` through
 * {@link LocalWebAuthnStore.claimDpopProof} — this function is pure and cannot
 * detect replay by itself.
 */
export async function verifyDpopProof(input: DpopVerificationInput): Promise<DpopVerification> {
  const now = input.now ?? Date.now();
  const skewMs = input.skewMs ?? 60_000;

  const segments = input.proof.split('.');
  if (segments.length !== 3) {
    return invalid('malformed_proof');
  }
  const [headerSegment, payloadSegment, signatureSegment] = segments;

  const header = parseJsonSegment(headerSegment);
  if (!header) {
    return invalid('malformed_header');
  }
  if (header.typ !== 'dpop+jwt') {
    return invalid('unexpected_typ');
  }
  if (typeof header.alg !== 'string' || !SUPPORTED_ALGORITHMS.has(header.alg)) {
    return invalid('unsupported_alg');
  }
  if (typeof header.jwk !== 'object' || header.jwk === null) {
    return invalid('missing_jwk');
  }
  // A private component in the header would mean the client shipped its key; it
  // is also the classic key-confusion vector, so refuse rather than ignore it.
  if ('d' in (header.jwk as Record<string, unknown>)) {
    return invalid('private_key_in_jwk');
  }

  const expectedJwk = coseToJwk(input.publicKeyCose);
  if (!expectedJwk) {
    return invalid('unsupported_credential_key');
  }
  if (!isPublicJwk(header.jwk)) {
    return invalid('malformed_jwk');
  }
  const expectedThumbprint = await jwkThumbprint(expectedJwk);
  const presentedThumbprint = await jwkThumbprint(header.jwk);
  const encoder = new TextEncoder();
  if (!equalBytes(encoder.encode(expectedThumbprint), encoder.encode(presentedThumbprint))) {
    return invalid('key_mismatch');
  }

  const signature = decodeBase64Url(signatureSegment);
  if (!signature) {
    return invalid('malformed_signature');
  }
  const verified = await verifySignature(
    expectedJwk,
    header.alg,
    `${headerSegment}.${payloadSegment}`,
    signature,
  );
  if (!verified) {
    return invalid('bad_signature');
  }

  const payload = parseJsonSegment(payloadSegment);
  if (!payload) {
    return invalid('malformed_payload');
  }
  if (typeof payload.jti !== 'string' || payload.jti.length < 8 || payload.jti.length > 256) {
    return invalid('bad_jti');
  }
  if (typeof payload.htm !== 'string' || payload.htm !== input.method.toUpperCase()) {
    return invalid('htm_mismatch');
  }
  const expectedUri = normalizeTargetUri(input.url);
  const presentedUri = typeof payload.htu === 'string' ? normalizeTargetUri(payload.htu) : null;
  if (!expectedUri || !presentedUri || expectedUri !== presentedUri) {
    return invalid('htu_mismatch');
  }
  if (typeof payload.iat !== 'number' || !Number.isFinite(payload.iat)) {
    return invalid('bad_iat');
  }
  const iatMs = payload.iat * 1000;
  if (iatMs > now + skewMs || iatMs < now - skewMs) {
    return invalid('iat_out_of_window');
  }
  const expectedAth = encodeBase64Url(await sha256(input.accessToken));
  if (
    typeof payload.ath !== 'string' ||
    !equalBytes(encoder.encode(expectedAth), encoder.encode(payload.ath))
  ) {
    return invalid('ath_mismatch');
  }
  if (input.nonces && input.nonces.length > 0) {
    // Both "absent" and "stale" report the same reason, so the host answers with
    // one `use_dpop_nonce` challenge either way and the client just retries.
    if (typeof payload.nonce !== 'string' || !input.nonces.includes(payload.nonce)) {
      return invalid('use_dpop_nonce');
    }
  }

  return {
    valid: true,
    jtiHash: await sha256(payload.jti),
    // The proof cannot be presented again once `iat` leaves the window, so the
    // replay entry only needs to outlive the window itself.
    expiresAt: iatMs + skewMs,
  };
}
