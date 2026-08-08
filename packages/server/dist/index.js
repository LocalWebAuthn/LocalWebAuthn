// src/crypto.ts
var BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
function defaultRandomBytes(length) {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}
async function sha256(value) {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const ownedBytes = Uint8Array.from(bytes);
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", ownedBytes.buffer));
}
function encodeBase32(bytes) {
  let bits = 0;
  let accumulator = 0;
  let output = "";
  for (const byte of bytes) {
    accumulator = accumulator << 8 | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += BASE32_ALPHABET[accumulator >>> bits & 31];
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[accumulator << 5 - bits & 31];
  }
  return output;
}
function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) {
    return null;
  }
  try {
    const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
    const padding = "=".repeat((4 - normalized.length % 4) % 4);
    const binary = atob(normalized + padding);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}
function equalBytes(left, right) {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}
function createUserHandle(randomBytes = defaultRandomBytes) {
  return randomBytes(32);
}
function createEnrollmentToken(randomBytes = defaultRandomBytes) {
  return encodeBase32(randomBytes(32));
}
function createOpaqueToken(randomBytes = defaultRandomBytes) {
  return encodeBase64Url(randomBytes(32));
}

// src/errors.ts
var LocalWebAuthnError = class extends Error {
  code;
  status;
  constructor(code, message, status) {
    super(message);
    this.name = "LocalWebAuthnError";
    this.code = code;
    this.status = status;
  }
};
function isLocalWebAuthnError(value) {
  return value instanceof LocalWebAuthnError;
}

// src/http.ts
function isHttpsPublicOrigin(publicOrigin) {
  return new URL(publicOrigin).protocol === "https:";
}
function isLoopbackHost(hostname) {
  return hostname === "localhost" || hostname.endsWith(".localhost") || hostname === "127.0.0.1" || hostname === "[::1]";
}
function assertSupportedPublicOrigin(publicOrigin) {
  const url = new URL(publicOrigin);
  if (url.protocol !== "https:" && !isLoopbackHost(url.hostname)) {
    throw new Error(`publicOrigin must be HTTPS (or loopback for development): ${url.origin}`);
  }
  return url;
}
function authCookieNames(publicOrigin, namespace = "lwa") {
  const base = namespace.replaceAll(/[^a-z0-9_-]/giu, "") || "lwa";
  const host = assertSupportedPublicOrigin(publicOrigin).protocol === "https:";
  const prefix = host ? `__Host-${base}` : base;
  return {
    challenge: `${prefix}_challenge`,
    enrollment: `${prefix}_enrollment`,
    session: `${prefix}_session`
  };
}
function cookieAttributes(options) {
  const secure = assertSupportedPublicOrigin(options.publicOrigin).protocol === "https:";
  const attributes = {
    httpOnly: true,
    path: "/",
    sameSite: "Strict",
    secure
  };
  if (options.expiresAt !== void 0) {
    const now = options.now?.() ?? Date.now();
    attributes.maxAge = Math.max(1, Math.ceil((options.expiresAt - now) / 1e3));
  }
  return attributes;
}
function isExactOrigin(requestOrigin, expectedOrigin) {
  if (requestOrigin == null || requestOrigin === "") {
    return false;
  }
  try {
    return new URL(requestOrigin).origin === new URL(expectedOrigin).origin;
  } catch {
    return false;
  }
}
function parseCookieHeader(header) {
  if (!header) {
    return {};
  }
  const cookies = {};
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) {
      continue;
    }
    const separator = trimmed.indexOf("=");
    if (separator <= 0) {
      continue;
    }
    const name = trimmed.slice(0, separator).trim();
    const value = trimmed.slice(separator + 1).trim();
    if (name && !(name in cookies)) {
      cookies[name] = value;
    }
  }
  return cookies;
}
var COOKIE_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
var COOKIE_VALUE = /^[\u0021\u0023-\u002B\u002D-\u003A\u003C-\u005B\u005D-\u007E]*$/u;
function serializeCookie(name, value, attributes) {
  if (!COOKIE_NAME.test(name)) {
    throw new TypeError(`Invalid cookie name: ${JSON.stringify(name)}`);
  }
  if (!COOKIE_VALUE.test(value)) {
    throw new TypeError("Invalid cookie value: not RFC 6265 cookie-octets.");
  }
  const segments = [
    `${name}=${value}`,
    `Path=${attributes.path}`,
    `SameSite=${attributes.sameSite}`
  ];
  segments.push("HttpOnly");
  if (attributes.secure) {
    segments.push("Secure");
  }
  if (attributes.maxAge !== void 0) {
    segments.push(`Max-Age=${String(attributes.maxAge)}`);
  }
  return segments.join("; ");
}
function serializeClearedCookie(name, publicOrigin) {
  return serializeCookie(name, "", {
    ...cookieAttributes({ publicOrigin }),
    maxAge: 0
  });
}

// src/signup.ts
function signupPhase(facts) {
  if (facts.hasActiveCredential) {
    return "enrolled";
  }
  if (facts.hasEnrollmentSession) {
    return "enrollment_exchanged";
  }
  if (facts.hasPendingEnrollmentGrant) {
    return "enrollment_issued";
  }
  return "created";
}
function nextSignupStep(phase) {
  switch (phase) {
    case "created":
      return {
        action: "issue_enrollment",
        reason: "Create a one-time enrollment grant after your identity checks pass."
      };
    case "enrollment_issued":
      return {
        action: "deliver_enrollment_url",
        reason: "Deliver the enrollment URL on a channel bound to the person; wait for exchange."
      };
    case "enrollment_exchanged":
      return {
        action: "register_passkey",
        reason: "Browser should call register options/verify to create the first passkey."
      };
    case "enrolled":
      return {
        action: "done",
        reason: "User has an active passkey; use session auth and optional additional passkeys."
      };
  }
}
function describeSignupPhase(phase) {
  switch (phase) {
    case "created":
      return "User exists; no enrollment grant yet";
    case "enrollment_issued":
      return "Enrollment link outstanding; no passkey yet";
    case "enrollment_exchanged":
      return "Enrollment session active; passkey registration in progress";
    case "enrolled":
      return "At least one active passkey";
  }
}
var SELF_SERVE_SIGNUP_STEPS = [
  "Collect identifiers (e.g. email and phone) and rate-limit the form",
  "Verify control of two independent channels before creating durable access",
  "Insert application user with createUserHandle(); do not store a password",
  "Call issueEnrollment(userId); store only the URL for delivery, never log the raw token long-term",
  "Deliver the enrollment URL on a bound channel (not an attacker-supplied address)",
  "User opens fragment \u2192 exchangeEnrollment \u2192 registerPasskey",
  "Optionally prompt for a second passkey while the session is fresh"
];

// src/service.ts
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse
} from "@simplewebauthn/server";

// src/config.ts
var DEFAULTS = {
  enrollmentGrantMs: 30 * 6e4,
  enrollmentSessionMs: 10 * 6e4,
  challengeMs: 5 * 6e4,
  sessionIdleMs: 30 * 6e4,
  sessionAbsoluteMs: 8 * 60 * 6e4
};
function configurationError(message) {
  throw new LocalWebAuthnError("invalid_configuration", message, 500);
}
function normalizeConfig(options) {
  const rpName = options.rpName.trim();
  const rpId = options.rpId.trim().toLowerCase();
  const configuredOrigins = typeof options.expectedOrigins === "string" ? [options.expectedOrigins] : options.expectedOrigins;
  if (!rpName || !rpId || configuredOrigins.length === 0) {
    configurationError("rpName, rpId, and at least one expected origin are required.");
  }
  try {
    const url = new URL(`https://${rpId}`);
    if (url.hostname !== rpId) {
      configurationError("rpId must be a bare hostname (no protocol, port, or path).");
    }
  } catch {
    configurationError("rpId must be a valid hostname.");
  }
  const expectedOrigins = configuredOrigins.map((configuredOrigin) => {
    const url = new URL(configuredOrigin);
    const origin = url.origin;
    const isLocalHttp = url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1");
    if (configuredOrigin !== origin || url.protocol !== "https:" && !isLocalHttp) {
      configurationError("Expected origins must be exact HTTPS origins or local HTTP origins.");
    }
    if (url.hostname !== rpId && !url.hostname.endsWith(`.${rpId}`)) {
      configurationError("Every expected origin hostname must equal or be beneath the RP ID.");
    }
    return origin;
  });
  const publicOrigin = options.publicOrigin ?? expectedOrigins[0];
  if (!expectedOrigins.includes(new URL(publicOrigin).origin) || publicOrigin !== new URL(publicOrigin).origin) {
    configurationError("publicOrigin must exactly match one of the expected origins.");
  }
  const enrollmentPath = options.enrollmentPath ?? "/enroll";
  if (!enrollmentPath.startsWith("/") || enrollmentPath.includes("#") || enrollmentPath.includes("?")) {
    configurationError("enrollmentPath must be an absolute URL path without a query or fragment.");
  }
  const durations = { ...DEFAULTS, ...options.durations };
  for (const [name, duration] of Object.entries(durations)) {
    if (!Number.isSafeInteger(duration) || duration <= 0) {
      configurationError(`${name} must be a positive integer number of milliseconds.`);
    }
  }
  if (durations.sessionIdleMs > durations.sessionAbsoluteMs) {
    configurationError("sessionIdleMs cannot exceed sessionAbsoluteMs.");
  }
  const credentialKinds = {};
  for (const [kind, policy] of Object.entries(options.credentialKinds ?? {})) {
    if (!kind.trim()) {
      configurationError("A credential kind cannot be an empty string.");
    }
    const sessionAbsoluteMs = policy.sessionAbsoluteMs ?? durations.sessionAbsoluteMs;
    for (const [name, duration] of Object.entries({
      sessionAbsoluteMs,
      sessionIdleMs: policy.sessionIdleMs ?? durations.sessionIdleMs
    })) {
      if (!Number.isSafeInteger(duration) || duration <= 0) {
        configurationError(
          `credentialKinds.${kind}.${name} must be a positive integer number of milliseconds.`
        );
      }
    }
    if (policy.sessionIdleMs !== void 0 && policy.sessionIdleMs > sessionAbsoluteMs) {
      configurationError(`credentialKinds.${kind}.sessionIdleMs cannot exceed sessionAbsoluteMs.`);
    }
    const sessionIdleMs = Math.min(
      policy.sessionIdleMs ?? durations.sessionIdleMs,
      sessionAbsoluteMs
    );
    credentialKinds[kind] = {
      interactive: policy.interactive ?? true,
      canRegister: policy.canRegister ?? true,
      sessionAbsoluteMs,
      sessionIdleMs
    };
  }
  let dpopNonce = null;
  if (options.dpopNonce) {
    const rotationMs = options.dpopNonce.rotationMs ?? 5 * 6e4;
    if (!Number.isSafeInteger(rotationMs) || rotationMs <= 0) {
      configurationError("dpopNonce.rotationMs must be a positive integer number of milliseconds.");
    }
    dpopNonce = { rotationMs };
  }
  return {
    rpName,
    rpId,
    expectedOrigins,
    publicOrigin,
    enrollmentPath,
    durations,
    credentialKinds,
    dpopNonce
  };
}
function defaultKindPolicy(config) {
  return {
    interactive: true,
    canRegister: true,
    sessionAbsoluteMs: config.durations.sessionAbsoluteMs,
    sessionIdleMs: config.durations.sessionIdleMs
  };
}
function kindPolicy(config, kind) {
  return (kind === null ? void 0 : config.credentialKinds[kind]) ?? defaultKindPolicy(config);
}

// src/dpop.ts
import { cose, decodeCredentialPublicKey } from "@simplewebauthn/server/helpers";
var SUPPORTED_ALGORITHMS = /* @__PURE__ */ new Set(["ES256", "EdDSA"]);
function invalid(reason) {
  return { valid: false, reason };
}
function coseToJwk(publicKeyCose) {
  let decoded;
  try {
    decoded = decodeCredentialPublicKey(Uint8Array.from(publicKeyCose));
  } catch {
    return null;
  }
  if (cose.isCOSEPublicKeyEC2(decoded)) {
    const crv = decoded.get(cose.COSEKEYS.crv);
    const x = decoded.get(cose.COSEKEYS.x);
    const y = decoded.get(cose.COSEKEYS.y);
    if (crv !== cose.COSECRV.P256 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) {
      return null;
    }
    return { kty: "EC", crv: "P-256", x: encodeBase64Url(x), y: encodeBase64Url(y) };
  }
  if (cose.isCOSEPublicKeyOKP(decoded)) {
    const crv = decoded.get(cose.COSEKEYS.crv);
    const x = decoded.get(cose.COSEKEYS.x);
    if (crv !== cose.COSECRV.ED25519 || !(x instanceof Uint8Array) || x.length !== 32) {
      return null;
    }
    return { kty: "OKP", crv: "Ed25519", x: encodeBase64Url(x) };
  }
  return null;
}
async function jwkThumbprint(jwk) {
  const canonical = jwk.kty === "EC" ? `{"crv":"${jwk.crv}","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}` : `{"crv":"${jwk.crv}","kty":"OKP","x":"${jwk.x}"}`;
  return encodeBase64Url(await sha256(canonical));
}
function parseJsonSegment(segment) {
  const bytes = decodeBase64Url(segment);
  if (!bytes) {
    return null;
  }
  try {
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    return typeof parsed === "object" && parsed !== null ? parsed : null;
  } catch {
    return null;
  }
}
function normalizeTargetUri(value) {
  try {
    const url = new URL(value);
    return `${url.origin}${url.pathname}`;
  } catch {
    return null;
  }
}
async function verifySignature(jwk, algorithm, signingInput, signature) {
  const parameters = algorithm === "ES256" ? { name: "ECDSA", namedCurve: "P-256" } : { name: "Ed25519" };
  const verifyParameters = algorithm === "ES256" ? { name: "ECDSA", hash: "SHA-256" } : { name: "Ed25519" };
  try {
    const key = await globalThis.crypto.subtle.importKey("jwk", jwk, parameters, false, ["verify"]);
    return await globalThis.crypto.subtle.verify(
      verifyParameters,
      key,
      Uint8Array.from(signature),
      new TextEncoder().encode(signingInput)
    );
  } catch {
    return false;
  }
}
async function verifyDpopProof(input) {
  const now = input.now ?? Date.now();
  const skewMs = input.skewMs ?? 6e4;
  const segments = input.proof.split(".");
  if (segments.length !== 3) {
    return invalid("malformed_proof");
  }
  const [headerSegment, payloadSegment, signatureSegment] = segments;
  const header = parseJsonSegment(headerSegment);
  if (!header) {
    return invalid("malformed_header");
  }
  if (header.typ !== "dpop+jwt") {
    return invalid("unexpected_typ");
  }
  if (typeof header.alg !== "string" || !SUPPORTED_ALGORITHMS.has(header.alg)) {
    return invalid("unsupported_alg");
  }
  if (typeof header.jwk !== "object" || header.jwk === null) {
    return invalid("missing_jwk");
  }
  if ("d" in header.jwk) {
    return invalid("private_key_in_jwk");
  }
  const expectedJwk = coseToJwk(input.publicKeyCose);
  if (!expectedJwk) {
    return invalid("unsupported_credential_key");
  }
  const expectedThumbprint = await jwkThumbprint(expectedJwk);
  let presentedThumbprint;
  try {
    presentedThumbprint = await jwkThumbprint(header.jwk);
  } catch {
    return invalid("malformed_jwk");
  }
  const encoder = new TextEncoder();
  if (!equalBytes(encoder.encode(expectedThumbprint), encoder.encode(presentedThumbprint))) {
    return invalid("key_mismatch");
  }
  const signature = decodeBase64Url(signatureSegment);
  if (!signature) {
    return invalid("malformed_signature");
  }
  const verified = await verifySignature(
    expectedJwk,
    header.alg,
    `${headerSegment}.${payloadSegment}`,
    signature
  );
  if (!verified) {
    return invalid("bad_signature");
  }
  const payload = parseJsonSegment(payloadSegment);
  if (!payload) {
    return invalid("malformed_payload");
  }
  if (typeof payload.jti !== "string" || payload.jti.length < 8 || payload.jti.length > 256) {
    return invalid("bad_jti");
  }
  if (typeof payload.htm !== "string" || payload.htm !== input.method.toUpperCase()) {
    return invalid("htm_mismatch");
  }
  const expectedUri = normalizeTargetUri(input.url);
  const presentedUri = typeof payload.htu === "string" ? normalizeTargetUri(payload.htu) : null;
  if (!expectedUri || !presentedUri || expectedUri !== presentedUri) {
    return invalid("htu_mismatch");
  }
  if (typeof payload.iat !== "number" || !Number.isFinite(payload.iat)) {
    return invalid("bad_iat");
  }
  const iatMs = payload.iat * 1e3;
  if (iatMs > now + skewMs || iatMs < now - skewMs) {
    return invalid("iat_out_of_window");
  }
  const expectedAth = encodeBase64Url(await sha256(input.accessToken));
  if (typeof payload.ath !== "string" || !equalBytes(encoder.encode(expectedAth), encoder.encode(payload.ath))) {
    return invalid("ath_mismatch");
  }
  if (input.nonces && input.nonces.length > 0) {
    if (typeof payload.nonce !== "string" || !input.nonces.includes(payload.nonce)) {
      return invalid("use_dpop_nonce");
    }
  }
  return {
    valid: true,
    jtiHash: await sha256(payload.jti),
    // The proof cannot be presented again once `iat` leaves the window, so the
    // replay entry only needs to outlive the window itself.
    expiresAt: iatMs + skewMs
  };
}

// src/types.ts
function toWebAuthnCredential(credential) {
  return {
    id: credential.id,
    // Uint8Array.from narrows ArrayBufferLike to ArrayBuffer for the SimpleWebAuthn types.
    publicKey: Uint8Array.from(credential.publicKey),
    counter: credential.counter,
    transports: credential.transports
  };
}

// src/service.ts
var defaultCeremonies = {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
};
function normalizeKind(kind) {
  const trimmed = kind?.trim() ?? "";
  return trimmed === "" ? null : trimmed;
}
var LocalWebAuthn = class {
  /** Normalized configuration (see {@link LocalWebAuthnOptions}). */
  config;
  #store;
  #users;
  #now;
  #randomBytes;
  #ceremonies;
  #onEvent;
  #logger;
  /** Widest idle window across the global setting and every declared kind. */
  #widestIdleMs;
  constructor(options) {
    this.config = normalizeConfig(options);
    this.#widestIdleMs = Math.max(
      this.config.durations.sessionIdleMs,
      ...Object.values(this.config.credentialKinds).map((policy) => policy.sessionIdleMs)
    );
    this.#store = options.store;
    this.#users = options.users;
    this.#now = options.now ?? Date.now;
    this.#randomBytes = options.randomBytes ?? defaultRandomBytes;
    this.#ceremonies = options.ceremonies ?? defaultCeremonies;
    this.#onEvent = options.onEvent;
    this.#logger = options.logger ?? console;
  }
  /**
   * Issue a single-use enrollment grant for a user.
   *
   * If the user already has a pending (uncompleted) enrollment grant, it is
   * revoked in the same operation. The revoked IDs are returned as
   * `supersededGrantIds` so the host can record the replacement durably from
   * the return value; an `enrollment.revoked` event is also emitted per prior
   * grant, but events are best-effort and must not be the only record.
   *
   * Throws `invalid_enrollment` (404) if the user is unknown or **inactive** —
   * the `getUser` provider returned `null`, `active: false`, or a
   * `webAuthnUserHandle` that is not 32 bytes.
   *
   * @param userId - The application user ID to enroll.
   * @param approvedByUserId - Optional ID of the administrator who approved this enrollment.
   * @returns The enrollment URL (with `#token=` fragment), raw token, expiry,
   *   and the IDs of any grants this issue superseded.
   */
  async issueEnrollment(userId, approvedByUserIdOrOptions) {
    const options = typeof approvedByUserIdOrOptions === "string" ? { approvedByUserId: approvedByUserIdOrOptions } : approvedByUserIdOrOptions ?? {};
    const credentialKind = normalizeKind(options.credentialKind);
    const user = await this.#activeUser(userId);
    if (!user) {
      throw new LocalWebAuthnError(
        "invalid_enrollment",
        "Enrollment cannot be issued for this user.",
        404
      );
    }
    const now = this.#now();
    const grantId = createOpaqueToken(this.#randomBytes);
    const enrollmentToken = createEnrollmentToken(this.#randomBytes);
    const expiresAt = now + this.config.durations.enrollmentGrantMs;
    const revokedGrantIds = await this.#store.replaceEnrollmentGrant({
      id: grantId,
      userId,
      tokenHash: await sha256(enrollmentToken),
      expiresAt,
      approvedByUserId: options.approvedByUserId ?? null,
      credentialKind,
      createdAt: now
    });
    for (const revokedGrantId of revokedGrantIds) {
      await this.#emit({
        type: "enrollment.revoked",
        at: now,
        userId,
        grantId: revokedGrantId
      });
    }
    const enrollmentUrl = new URL(this.config.enrollmentPath, this.config.publicOrigin);
    enrollmentUrl.hash = `token=${enrollmentToken}`;
    await this.#emit({ type: "enrollment.issued", at: now, userId, grantId });
    return {
      grantId,
      enrollmentToken,
      enrollmentUrl: enrollmentUrl.toString(),
      expiresAt,
      supersededGrantIds: revokedGrantIds
    };
  }
  /**
   * Exchange a one-time enrollment token for an enrollment session.
   *
   * The token is single-use — subsequent exchanges with the same token will fail.
   * The returned `enrollmentSessionToken` must be stored in an HTTP-only cookie
   * and passed to {@link registrationOptions} and {@link verifyRegistration}.
   *
   * Throws `invalid_enrollment` (400) for a malformed token, and
   * `invalid_enrollment` (403) when the token is unknown, expired, already
   * exchanged, revoked — or when the user is **inactive** as reported by the
   * `getUser` provider, so deactivating a user refuses their outstanding
   * enrollment links.
   *
   * @param enrollmentToken - The raw token from the enrollment URL fragment.
   * @returns The enrollment session and public user identity.
   */
  async exchangeEnrollment(enrollmentToken) {
    const token = enrollmentToken.toLowerCase();
    if (!/^[a-z2-7]{52}$/u.test(token)) {
      throw new LocalWebAuthnError("invalid_enrollment", "The enrollment link is invalid.", 400);
    }
    const now = this.#now();
    const enrollmentSessionToken = createOpaqueToken(this.#randomBytes);
    const sessionHash = await sha256(enrollmentSessionToken);
    const session = await this.#store.exchangeEnrollment(
      await sha256(token),
      sessionHash,
      now + this.config.durations.enrollmentSessionMs,
      now
    );
    const user = session ? await this.#activeUser(session.userId) : null;
    if (!session || !user) {
      throw new LocalWebAuthnError(
        "invalid_enrollment",
        "The enrollment link is invalid or expired.",
        403
      );
    }
    await this.#emit({
      type: "enrollment.exchanged",
      at: now,
      userId: user.id,
      grantId: session.grantId
    });
    return {
      enrollmentSessionToken,
      expiresAt: session.sessionExpiresAt,
      user: this.#publicUser(user)
    };
  }
  /**
   * Create passkey-creation options bound to a registration authorization.
   *
   * Authorization is exactly one of: an exchanged enrollment session (the
   * user's first passkey) or an authenticated session (an additional passkey).
   * The returned single-use `challengeToken` must come back through
   * {@link verifyRegistration}, typically via an HTTP-only cookie.
   *
   * Throws `enrollment_not_authorized` (403) when neither authorization is
   * valid — including when the user is **inactive** as reported by the
   * `getUser` provider.
   */
  async registrationOptions(input) {
    const authorization = await this.#registrationAuthorization(input);
    const requested = normalizeKind(input.credentialKind);
    const granted = authorization.grantCredentialKind;
    if (granted !== null && requested !== null && granted !== requested) {
      throw new LocalWebAuthnError(
        "invalid_configuration",
        `This enrollment grant authorizes credential kind ${JSON.stringify(granted)}, but the route asked for ${JSON.stringify(requested)}.`,
        500
      );
    }
    const credentialKind = granted ?? requested;
    const credentials = await this.#store.listCredentials(authorization.user.id);
    const options = await this.#ceremonies.generateRegistrationOptions({
      rpName: this.config.rpName,
      rpID: this.config.rpId,
      userID: Uint8Array.from(authorization.user.webAuthnUserHandle),
      userName: authorization.user.name,
      userDisplayName: authorization.user.displayName,
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required"
      },
      excludeCredentials: credentials.map((credential) => ({
        id: credential.id,
        transports: credential.transports
      }))
    });
    const now = this.#now();
    const challengeToken = createOpaqueToken(this.#randomBytes);
    const expiresAt = now + this.config.durations.challengeMs;
    if (!await this.#store.createChallenge({
      idHash: await sha256(challengeToken),
      kind: "registration",
      challenge: options.challenge,
      userId: authorization.user.id,
      grantId: authorization.grantId,
      authorizationSessionHash: authorization.authenticatedSessionHash,
      credentialKind,
      allowedCredentialKinds: null,
      expiresAt,
      createdAt: now
    })) {
      throw new LocalWebAuthnError(
        "invalid_ceremony",
        "A challenge token collision occurred; retry the ceremony.",
        409
      );
    }
    return { options, challengeToken, expiresAt };
  }
  /**
   * Verify a registration response, store the credential, and open a session.
   *
   * The challenge is consumed exactly once, the registration authorization is
   * re-checked, and the store commits credential + grant completion + initial
   * session atomically (see the D1 caveat in SECURITY.md).
   *
   * Throws `invalid_ceremony` (400) for an unknown, expired, or replayed
   * challenge; `enrollment_not_authorized` (403) when the enrollment or
   * authenticated session no longer authorizes this challenge — including when
   * the user is **inactive** as reported by the `getUser` provider; and
   * `registration_failed` (400, or 409 when authorization was lost at commit
   * time) when the WebAuthn response does not verify. Unexpected storage
   * failures propagate as thrown errors rather than being misreported as an
   * expired authorization.
   */
  async verifyRegistration(input) {
    const now = this.#now();
    const challenge = await this.#store.consumeChallenge(
      await sha256(input.challengeToken),
      "registration",
      now
    );
    if (!challenge?.userId) {
      throw new LocalWebAuthnError(
        "invalid_ceremony",
        "The registration ceremony is invalid or expired.",
        400
      );
    }
    const authorization = await this.#verifyRegistrationAuthorization(challenge, input);
    const user = await this.#activeUser(challenge.userId);
    if (!authorization || !user) {
      throw new LocalWebAuthnError(
        "enrollment_not_authorized",
        "A valid enrollment or authenticated session is required.",
        403
      );
    }
    let verification;
    try {
      verification = await this.#ceremonies.verifyRegistrationResponse({
        response: input.response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: this.config.expectedOrigins,
        expectedRPID: this.config.rpId,
        requireUserVerification: true
      });
    } catch {
      throw new LocalWebAuthnError(
        "registration_failed",
        "The passkey could not be verified.",
        400
      );
    }
    if (!verification.verified) {
      throw new LocalWebAuthnError(
        "registration_failed",
        "The passkey could not be verified.",
        400
      );
    }
    const { credential, credentialBackedUp, credentialDeviceType } = verification.registrationInfo;
    const sessionToken = createOpaqueToken(this.#randomBytes);
    const expiresAt = now + kindPolicy(this.config, challenge.credentialKind).sessionAbsoluteMs;
    const completed = await this.#store.completeRegistration({
      challenge,
      enrollmentSessionHash: authorization.enrollmentSessionHash,
      authenticatedSessionHash: authorization.authenticatedSessionHash,
      credential: {
        id: credential.id,
        userId: user.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: credential.transports ?? [],
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        label: this.#credentialLabel(input.label, credentialDeviceType, challenge.credentialKind),
        // Taken from the challenge, which the host wrote before the client saw
        // it — never from `input`, which is shaped by the request body.
        kind: challenge.credentialKind,
        // Heritage, from the authorization that permitted this registration. The
        // rows that carry it — the consumed challenge, the completed grant, the
        // authorizing session — are all reaped within minutes, so this is the only
        // durable record of where the credential came from.
        createdVia: authorization.grantId === null ? "credential" : "enrollment",
        parentCredentialId: authorization.parentCredentialId,
        grantId: authorization.grantId,
        approvedByUserId: authorization.approvedByUserId,
        createdAt: now
      },
      session: {
        idHash: await sha256(sessionToken),
        userId: user.id,
        credentialId: credential.id,
        authenticatedAt: now,
        expiresAt,
        lastSeenAt: now
      },
      now
    });
    if (!completed) {
      throw new LocalWebAuthnError(
        "registration_failed",
        "The registration authorization is no longer valid.",
        409
      );
    }
    if (challenge.grantId) {
      await this.#emit({
        type: "enrollment.completed",
        at: now,
        userId: user.id,
        grantId: challenge.grantId
      });
    }
    await this.#emit({
      type: "credential.registered",
      at: now,
      userId: user.id,
      credentialId: credential.id,
      credentialKind: challenge.credentialKind
    });
    await this.#emit({
      type: "session.created",
      at: now,
      userId: user.id,
      credentialId: credential.id,
      credentialKind: challenge.credentialKind
    });
    return {
      verified: true,
      sessionToken,
      expiresAt,
      credentialId: credential.id,
      credentialKind: challenge.credentialKind
    };
  }
  /**
   * Create discoverable-credential authentication options with
   * `userVerification: 'required'` and a single-use challenge token.
   *
   * No user is identified at this point; the authenticator chooses the
   * credential and {@link verifyAuthentication} resolves and checks the user.
   */
  async authenticationOptions(input = {}) {
    const options = await this.#ceremonies.generateAuthenticationOptions({
      rpID: this.config.rpId,
      userVerification: "required"
    });
    const now = this.#now();
    const challengeToken = createOpaqueToken(this.#randomBytes);
    const expiresAt = now + this.config.durations.challengeMs;
    if (!await this.#store.createChallenge({
      idHash: await sha256(challengeToken),
      kind: "authentication",
      challenge: options.challenge,
      userId: null,
      grantId: null,
      authorizationSessionHash: null,
      credentialKind: null,
      allowedCredentialKinds: this.#admissibleKinds(input.credentialKinds),
      expiresAt,
      createdAt: now
    })) {
      throw new LocalWebAuthnError(
        "invalid_ceremony",
        "A challenge token collision occurred; retry the ceremony.",
        409
      );
    }
    return { options, challengeToken, expiresAt };
  }
  /**
   * Verify an authentication assertion and create a session.
   *
   * Throws `invalid_ceremony` (400) for an unknown, expired, or replayed
   * challenge. Throws `authentication_failed` (401) when the credential is
   * unknown or revoked, the response's user handle does not match, the
   * signature does not verify, the signature counter does not advance — or the
   * user is **inactive** as reported by the `getUser` provider, so a
   * deactivated user is refused at the ceremony itself, not just at session
   * resolution. Throws `authentication_failed` (409) when the credential
   * changed concurrently (counter compare-and-swap lost).
   */
  async verifyAuthentication(input) {
    const now = this.#now();
    const challenge = await this.#store.consumeChallenge(
      await sha256(input.challengeToken),
      "authentication",
      now
    );
    if (!challenge) {
      throw new LocalWebAuthnError(
        "invalid_ceremony",
        "The authentication ceremony is invalid or expired.",
        400
      );
    }
    const credential = await this.#store.getCredential(input.response.id);
    const user = credential ? await this.#activeUser(credential.userId) : null;
    const responseHandle = input.response.response.userHandle ? decodeBase64Url(input.response.response.userHandle) : null;
    if (!credential || credential.revokedAt !== null || !user || !responseHandle || !equalBytes(responseHandle, user.webAuthnUserHandle) || // The ceremony declared which credential kinds it accepts, before this
    // client was handed a challenge. A machine credential presenting itself at
    // the browser sign-in route fails here, and vice versa — enforced once,
    // centrally, rather than in every host route.
    !this.#kindAdmitted(credential.kind, challenge.allowedCredentialKinds)) {
      throw new LocalWebAuthnError(
        "authentication_failed",
        "The passkey could not be verified.",
        401
      );
    }
    let verification;
    try {
      verification = await this.#ceremonies.verifyAuthenticationResponse({
        response: input.response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: this.config.expectedOrigins,
        expectedRPID: this.config.rpId,
        credential: toWebAuthnCredential(credential),
        requireUserVerification: true
      });
    } catch {
      throw new LocalWebAuthnError(
        "authentication_failed",
        "The passkey could not be verified.",
        401
      );
    }
    if (!verification.verified) {
      throw new LocalWebAuthnError(
        "authentication_failed",
        "The passkey could not be verified.",
        401
      );
    }
    const previousCounter = credential.counter;
    const newCounter = verification.authenticationInfo.newCounter;
    if ((previousCounter > 0 || newCounter > 0) && newCounter <= previousCounter) {
      throw new LocalWebAuthnError(
        "authentication_failed",
        "The passkey could not be verified.",
        401
      );
    }
    const sessionToken = createOpaqueToken(this.#randomBytes);
    const expiresAt = now + kindPolicy(this.config, credential.kind).sessionAbsoluteMs;
    const completed = await this.#store.completeAuthentication({
      credentialId: credential.id,
      previousCounter,
      newCounter,
      session: {
        idHash: await sha256(sessionToken),
        userId: user.id,
        credentialId: credential.id,
        authenticatedAt: now,
        expiresAt,
        lastSeenAt: now
      },
      now
    });
    if (!completed) {
      throw new LocalWebAuthnError(
        "authentication_failed",
        "The passkey changed during authentication.",
        409
      );
    }
    await this.#emit({
      type: "credential.authenticated",
      at: now,
      userId: user.id,
      credentialId: credential.id,
      credentialKind: credential.kind
    });
    await this.#emit({
      type: "session.created",
      at: now,
      userId: user.id,
      credentialId: credential.id,
      credentialKind: credential.kind
    });
    return {
      verified: true,
      sessionToken,
      expiresAt,
      credentialId: credential.id,
      credentialKind: credential.kind,
      user: this.#publicUser(user)
    };
  }
  /**
   * Resolve a session token to a user and session identity.
   *
   * Returns `null` if the session is expired, idle, revoked, the credential was
   * revoked, or the user is inactive.
   *
   * @param sessionToken - The raw opaque session token (from cookie).
   * @param touch - When `true` (default), update `lastSeenAt` to keep the session alive.
   */
  async resolveSession(sessionToken, touch = true) {
    const idHash = await sha256(sessionToken);
    const now = this.#now();
    const session = await this.#store.resolveSession(idHash, now, now - this.#widestIdleMs);
    const user = session ? await this.#activeUser(session.userId) : null;
    if (!session || !user) {
      return null;
    }
    if (session.lastSeenAt <= now - kindPolicy(this.config, session.credentialKind).sessionIdleMs) {
      return null;
    }
    if (touch && !await this.#store.touchSession(idHash, now)) {
      return null;
    }
    return { user, session: { ...session, lastSeenAt: touch ? now : session.lastSeenAt } };
  }
  /**
   * Revoke a single session by its raw token (logout).
   *
   * @returns `true` if a live session was revoked, `false` if the token was
   *   unknown or already revoked.
   */
  async revokeSession(sessionToken) {
    const now = this.#now();
    const revoked = await this.#store.revokeSession(await sha256(sessionToken), now);
    if (revoked) {
      await this.#emit({
        type: "session.revoked",
        at: now,
        userId: revoked.userId,
        credentialId: revoked.credentialId
      });
    }
    return revoked !== null;
  }
  /**
   * Revoke every live session for a user — "sign out everywhere" — without
   * touching credentials or enrollment grants.
   *
   * Use it when a session (not a passkey) is the problem: a suspected stolen
   * cookie, a self-service "sign out my other devices" control, or hygiene
   * when suspending a user. Deactivating a user (`getUser` returning
   * `active: false`) already blocks every ceremony and session resolution
   * immediately; this method additionally ends the session records themselves.
   * To revoke the passkeys too, use {@link revokeUserAuthentication}.
   *
   * Pass the caller's own cookie token as `exceptSessionToken` to spare it
   * ("sign out everywhere else"). Omit it to revoke every session, including
   * the caller's own — appropriate when the current machine may itself be
   * suspect. Emits a `user.sessions_revoked` event when at least one session
   * was revoked.
   *
   * Pass `kinds` to scope the revoke to sessions opened by credentials of those
   * {@link Credential.kind} values — "sign this person out of their devices
   * without stopping the nightly export". `null` is a legal member and matches
   * unclassified credentials.
   *
   * @param userId - The application user whose sessions end.
   * @param options.exceptSessionToken - Raw session token to leave live.
   * @param options.kinds - Restrict to sessions from credentials of these kinds.
   * @returns The number of live sessions revoked.
   */
  async revokeUserSessions(userId, options = {}) {
    const now = this.#now();
    const exceptHash = options.exceptSessionToken ? await sha256(options.exceptSessionToken) : void 0;
    let count;
    if (options.kinds) {
      const kinds = new Set(options.kinds);
      const credentials = await this.#store.listCredentials(userId, true);
      count = 0;
      for (const credential of credentials) {
        if (!kinds.has(credential.kind)) {
          continue;
        }
        count += await this.#store.revokeLiveCredentialSessions(
          credential.id,
          now,
          now - kindPolicy(this.config, credential.kind).sessionIdleMs,
          exceptHash
        );
      }
    } else {
      count = await this.#store.revokeUserSessions(
        userId,
        now,
        now - this.#widestIdleMs,
        exceptHash
      );
    }
    if (count > 0) {
      await this.#emit({
        type: "user.sessions_revoked",
        at: now,
        userId,
        count,
        ...options.kinds ? { kinds: options.kinds } : {}
      });
    }
    return count;
  }
  /**
   * Whether a credential of this {@link Credential.kind} may act through an
   * interactive (browser, cookie-bearing) route.
   *
   * Hosts that accept machine credentials **must** consult this at their session
   * middleware, not only at authentication. A machine credential holds a valid
   * session token, and a script can present it as a `Cookie` and write its own
   * `Origin` — so without this check it reaches every cookie-authenticated route.
   *
   * The one that matters is enrollment issuance. `canRegister: false` closes the
   * session registration path, but the *grant* path is authorized purely by
   * possession of a single-use enrollment token, with no session to inspect — so
   * the package cannot gate it, and a machine that can obtain a grant registers a
   * fresh credential and defeats `canRegister` entirely. Refusing non-interactive
   * kinds at the session middleware is what closes that, and it has to be the
   * host because only the host knows who is calling `issueEnrollment`.
   *
   * An undeclared kind — including `null` — is interactive, matching the
   * behaviour from before `credentialKinds` existed.
   */
  interactiveKind(kind) {
    return kindPolicy(this.config, kind).interactive;
  }
  /**
   * A credential and its ancestors, root first.
   *
   * The root is whichever credential came from an enrollment grant, so the chain
   * answers "who authorized this, and who authorized them" back to an
   * out-of-band approval. Credentials registered before heritage was recorded
   * have `parentCredentialId: null` and terminate the walk early with
   * `createdVia: null` — unknown rather than guessed.
   *
   * Returns `[]` for an unknown credential, or one belonging to another user.
   */
  credentialLineage(userId, credentialId) {
    return this.#store.credentialAncestry(userId, credentialId);
  }
  /**
   * A credential and everything descended from it, nearest first.
   *
   * Index 0 is the credential itself. This is the blast radius of a compromised
   * credential: everything it was used to enroll, and everything those enrolled.
   */
  credentialDescendants(userId, credentialId) {
    return this.#store.credentialDescendants(userId, credentialId);
  }
  /**
   * Revoke a credential and every credential descended from it.
   *
   * The remediation primitive for a compromised credential. A stolen session can
   * enroll another passkey — that is the intended "add a passkey" feature for a
   * person, and `canRegister` only restrains non-interactive kinds — so revoking
   * the credential you suspect can leave the attacker's behind, indistinguishable
   * from a legitimate one after the fact. This revokes the subtree.
   *
   * Revokes with `allowLastCredential`, because stopping short of emptying the
   * account would leave a partially-revoked tree, which is worse than requiring
   * re-enrollment after a compromise. The account may therefore be left with no
   * usable credential; that is the intent.
   *
   * @returns IDs actually revoked, root first. Already-revoked ones are skipped.
   */
  async revokeCredentialTree(userId, credentialId) {
    const now = this.#now();
    const subtree = await this.#store.credentialDescendants(userId, credentialId);
    const revoked = [];
    for (const credential of subtree) {
      if (credential.revokedAt !== null) {
        continue;
      }
      const result = await this.#store.revokeCredential(userId, credential.id, now, {
        allowLastCredential: true
      });
      if (result === "revoked") {
        revoked.push(credential.id);
        await this.#emit({
          type: "credential.revoked",
          at: now,
          userId,
          credentialId: credential.id,
          credentialKind: credential.kind
        });
      }
    }
    return revoked;
  }
  /** List a user's credentials; revoked ones only when `includeRevoked` is `true`. */
  listCredentials(userId, includeRevoked = false) {
    return this.#store.listCredentials(userId, includeRevoked);
  }
  /**
   * Revoke a single credential and all its sessions.
   *
   * Throws {@link LocalWebAuthnError} with code `"last_credential"` if this is
   * the user's only remaining active credential. Pass `{ allowLastCredential: true }`
   * to override this safeguard (e.g., during a recovery flow).
   *
   * @returns `true` if the credential was revoked, `false` if it was already revoked.
   */
  async revokeCredential(userId, credentialId, options = {}) {
    const now = this.#now();
    const result = await this.#store.revokeCredential(userId, credentialId, now, options);
    if (result === "last_credential") {
      throw new LocalWebAuthnError(
        "last_credential",
        "The final active credential cannot be revoked without a recovery flow.",
        409
      );
    }
    if (result === "revoked") {
      await this.#emit({
        type: "credential.revoked",
        at: now,
        userId,
        credentialId
      });
      return true;
    }
    return false;
  }
  /**
   * Revoke all of a user's credentials, sessions, pending enrollment grants,
   * and unconsumed challenges — the recovery reset.
   *
   * The user must re-enroll through a fresh {@link issueEnrollment} to sign in
   * again. To end sessions while keeping passkeys, use
   * {@link revokeUserSessions} instead.
   *
   * Pass `kinds` to scope the revoke to credentials of those
   * {@link Credential.kind} values — "revoke this person's machine access,
   * leave their passkeys". Two differences from the unscoped form:
   *
   * - Pending enrollment grants **of those kinds** are revoked too, but grants of
   *   other kinds and all unconsumed challenges are left alone. Revoking the
   *   grants matters: a live grant of kind X is standing authorization to create
   *   another credential of kind X, so leaving one would let the holder
   *   immediately re-enroll and undo the revoke.
   * - It is not a lockout. A surviving credential of another kind still
   *   authenticates as this user, so `{ kinds: ['person'] }` does *not* stop the
   *   account being used — it stops the person's own devices being used. Suspend
   *   the user through `getUser` returning `active: false` if that is the intent.
   */
  async revokeUserAuthentication(userId, options = {}) {
    const now = this.#now();
    if (options.kinds) {
      const kinds = new Set(options.kinds);
      const credentials = await this.#store.listCredentials(userId, true);
      for (const credential of credentials) {
        if (credential.revokedAt !== null || !kinds.has(credential.kind)) {
          continue;
        }
        await this.#store.revokeCredential(userId, credential.id, now, {
          allowLastCredential: true
        });
      }
      for (const kind of kinds) {
        for (const grantId of await this.#store.revokePendingEnrollmentGrants(userId, now, kind)) {
          await this.#emit({ type: "enrollment.revoked", at: now, userId, grantId });
        }
      }
    } else {
      await this.#store.revokeUserAuthentication(userId, now);
    }
    await this.#emit({
      type: "user.authentication_revoked",
      at: now,
      userId,
      ...options.kinds ? { kinds: options.kinds } : {}
    });
  }
  /**
   * Reap expired enrollment grants, finished challenges, and dead sessions.
   * Schedule periodically (every few minutes is ample); credentials are never
   * part of cleanup.
   */
  cleanup() {
    return this.#store.cleanup(this.#now());
  }
  async #registrationAuthorization(input) {
    const now = this.#now();
    if (input.enrollmentSessionToken) {
      const enrollmentSessionHash = await sha256(input.enrollmentSessionToken);
      const enrollment = await this.#store.resolveEnrollmentSession(enrollmentSessionHash, now);
      const user = enrollment ? await this.#activeUser(enrollment.userId) : null;
      if (enrollment && user) {
        return {
          user,
          grantId: enrollment.grantId,
          enrollmentSessionHash,
          authenticatedSessionHash: null,
          grantCredentialKind: enrollment.credentialKind,
          approvedByUserId: enrollment.approvedByUserId,
          parentCredentialId: null
        };
      }
    } else if (input.sessionToken) {
      const authenticatedSessionHash = await sha256(input.sessionToken);
      const resolved = await this.resolveSession(input.sessionToken, false);
      if (resolved) {
        if (!kindPolicy(this.config, resolved.session.credentialKind).canRegister) {
          throw new LocalWebAuthnError(
            "registration_not_permitted",
            "This credential may not register additional credentials.",
            403
          );
        }
        return {
          user: resolved.user,
          grantId: null,
          enrollmentSessionHash: null,
          authenticatedSessionHash,
          grantCredentialKind: null,
          approvedByUserId: null,
          // The session that authorized this registration knows which credential
          // opened it, so the parent link costs no extra lookup.
          parentCredentialId: resolved.session.credentialId
        };
      }
    }
    throw new LocalWebAuthnError(
      "enrollment_not_authorized",
      "A valid enrollment or authenticated session is required.",
      403
    );
  }
  /**
   * The `allowed_credential_kinds` value to record on an authentication challenge.
   *
   * An explicit list is stored as given, so a machine route can name its kind and
   * that decision is fixed on a server row before the client sees the challenge.
   *
   * With no list the column stays `null`, meaning "unconstrained by this
   * ceremony" — the admissibility question is then answered from configuration at
   * verification time by {@link #kindAdmitted}. Storing `null` rather than an
   * enumerated allow-list matters because the set of kinds present in the
   * database is not knowable from configuration alone.
   */
  #admissibleKinds(requested) {
    return requested ? [...new Set(requested)] : null;
  }
  /**
   * Whether `kind` may authenticate under a challenge's recorded constraint.
   *
   * An enumerated list is authoritative. An unconstrained challenge falls back to
   * the kind's `interactive` policy, so a kind declared `interactive: false` is
   * refused at any route that did not ask for it by name — while an undeclared
   * kind (including `null`) is admitted, preserving pre-`credentialKinds`
   * behaviour.
   */
  #kindAdmitted(kind, allowed) {
    return allowed === null ? kindPolicy(this.config, kind).interactive : allowed.includes(kind);
  }
  /** `floor(now / rotationMs)` — the same value on every server, from the clock alone. */
  #dpopSlot(now, rotationMs) {
    return Math.floor(now / rotationMs);
  }
  /**
   * The current nonce, for a `DPoP-Nonce` response header.
   *
   * Returns `null` when nonce issuance is not configured, so a host can attach the
   * header unconditionally and have it simply not appear.
   *
   * Every server in a deployment derives the same slot from its clock and claims
   * it through the store; whichever inserts first decides the value and the rest
   * read it back. No shared secret and no rotation coordination.
   */
  async dpopNonce() {
    if (!this.config.dpopNonce) {
      return null;
    }
    const { rotationMs } = this.config.dpopNonce;
    const now = this.#now();
    const slot = this.#dpopSlot(now, rotationMs);
    return this.#store.claimDpopNonce(
      slot,
      createOpaqueToken(this.#randomBytes),
      // Outlive the previous-slot grace window before becoming reapable.
      (slot + 3) * rotationMs
    );
  }
  /** Current and previous slot, so a rotation mid-flight does not reject a fresh proof. */
  async #acceptableDpopNonces(now) {
    if (!this.config.dpopNonce) {
      return [];
    }
    const { rotationMs } = this.config.dpopNonce;
    const slot = this.#dpopSlot(now, rotationMs);
    await this.#store.claimDpopNonce(
      slot,
      createOpaqueToken(this.#randomBytes),
      (slot + 3) * rotationMs
    );
    return this.#store.dpopNonces(slot, slot - 1);
  }
  /**
   * Verify a DPoP proof (RFC 9449) for a request on an already-resolved session.
   *
   * Derives the expected key thumbprint from the session's credential, so there
   * is no per-session key material to store, then claims the proof's `jti`
   * through the store so a captured proof cannot be replayed inside its `iat`
   * window.
   *
   * Throws `invalid_dpop_proof` (401) on any failure. The `reason` is attached to
   * the message for logs; do not surface it to callers, since it distinguishes
   * "wrong key" from "replayed".
   */
  async verifyDpop(input) {
    if (!input.proof) {
      throw new LocalWebAuthnError("invalid_dpop_proof", "A DPoP proof is required.", 401);
    }
    if (input.requireNonce && !this.config.dpopNonce) {
      throw new LocalWebAuthnError(
        "invalid_configuration",
        "requireNonce needs dpopNonce configuration; otherwise no nonce is ever issued.",
        500
      );
    }
    const credential = await this.#store.getCredential(input.session.credentialId);
    if (!credential || credential.revokedAt !== null) {
      throw new LocalWebAuthnError("invalid_dpop_proof", "The credential is unavailable.", 401);
    }
    const now = this.#now();
    const verification = await verifyDpopProof({
      proof: input.proof,
      method: input.method,
      url: input.url,
      accessToken: input.sessionToken,
      publicKeyCose: credential.publicKey,
      nonces: input.requireNonce ? await this.#acceptableDpopNonces(now) : void 0,
      now
    });
    if (!verification.valid) {
      throw new LocalWebAuthnError(
        verification.reason === "use_dpop_nonce" ? "dpop_nonce_required" : "invalid_dpop_proof",
        `The DPoP proof is not valid (${verification.reason}).`,
        401
      );
    }
    if (!await this.#store.claimDpopProof(verification.jtiHash, verification.expiresAt)) {
      throw new LocalWebAuthnError(
        "invalid_dpop_proof",
        "The DPoP proof is not valid (replayed).",
        401
      );
    }
  }
  async #verifyRegistrationAuthorization(challenge, input) {
    if (challenge.grantId && input.enrollmentSessionToken) {
      const enrollmentSessionHash = await sha256(input.enrollmentSessionToken);
      const enrollment = await this.#store.resolveEnrollmentSession(
        enrollmentSessionHash,
        this.#now()
      );
      return enrollment?.grantId === challenge.grantId ? {
        enrollmentSessionHash,
        authenticatedSessionHash: null,
        grantId: enrollment.grantId,
        approvedByUserId: enrollment.approvedByUserId,
        parentCredentialId: null
      } : null;
    }
    if (challenge.authorizationSessionHash && input.sessionToken) {
      const authenticatedSessionHash = await sha256(input.sessionToken);
      if (!equalBytes(authenticatedSessionHash, challenge.authorizationSessionHash)) {
        return null;
      }
      const session = await this.resolveSession(input.sessionToken, false);
      return session ? {
        enrollmentSessionHash: null,
        authenticatedSessionHash,
        grantId: null,
        approvedByUserId: null,
        // Re-read here rather than carried from `registrationOptions`: this is
        // the session that still holds at commit time, which is the one that
        // actually authorized the credential.
        parentCredentialId: session.session.credentialId
      } : null;
    }
    return null;
  }
  async #activeUser(userId) {
    const user = await this.#users.getUser(userId);
    return user?.active && user.webAuthnUserHandle.length === 32 ? user : null;
  }
  #publicUser(user) {
    return { id: user.id, name: user.name, displayName: user.displayName };
  }
  #credentialLabel(requestedLabel, deviceType, kind) {
    const label = requestedLabel?.trim();
    if (label) {
      return label.slice(0, 80);
    }
    if (kind !== null) {
      return kind.slice(0, 80);
    }
    return deviceType === "multiDevice" ? "Synced passkey" : "Device passkey";
  }
  async #emit(event) {
    if (!this.#onEvent) {
      return;
    }
    try {
      await this.#onEvent(event);
    } catch (error) {
      this.#logger.warn("LocalWebAuthn event handler failed.", { event: event.type, error });
    }
  }
};
export {
  LocalWebAuthn,
  LocalWebAuthnError,
  SELF_SERVE_SIGNUP_STEPS,
  authCookieNames,
  cookieAttributes,
  createEnrollmentToken,
  createOpaqueToken,
  createUserHandle,
  decodeBase64Url,
  describeSignupPhase,
  encodeBase32,
  encodeBase64Url,
  equalBytes,
  isExactOrigin,
  isHttpsPublicOrigin,
  isLocalWebAuthnError,
  nextSignupStep,
  parseCookieHeader,
  serializeClearedCookie,
  serializeCookie,
  sha256,
  signupPhase
};
