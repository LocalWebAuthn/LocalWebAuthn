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
  return {
    rpName,
    rpId,
    expectedOrigins,
    publicOrigin,
    enrollmentPath,
    durations
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
  constructor(options) {
    this.config = normalizeConfig(options);
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
   * implicitly revoked and an {@link LocalWebAuthnEvent.enrollment.revoked | `enrollment.revoked`}
   * audit event is emitted for the prior grant.
   *
   * @param userId - The application user ID to enroll.
   * @param approvedByUserId - Optional ID of the administrator who approved this enrollment.
   * @returns The enrollment URL (with `#token=` fragment), raw token, and expiry.
   */
  async issueEnrollment(userId, approvedByUserId) {
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
      approvedByUserId: approvedByUserId ?? null,
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
      expiresAt
    };
  }
  /**
   * Exchange a one-time enrollment token for an enrollment session.
   *
   * The token is single-use — subsequent exchanges with the same token will fail.
   * The returned `enrollmentSessionToken` must be stored in an HTTP-only cookie
   * and passed to {@link registrationOptions} and {@link verifyRegistration}.
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
  async registrationOptions(input) {
    const authorization = await this.#registrationAuthorization(input);
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
    const expiresAt = now + this.config.durations.sessionAbsoluteMs;
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
        label: this.#credentialLabel(input.label, credentialDeviceType),
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
      credentialId: credential.id
    });
    await this.#emit({
      type: "session.created",
      at: now,
      userId: user.id,
      credentialId: credential.id
    });
    return { verified: true, sessionToken, expiresAt, credentialId: credential.id };
  }
  async authenticationOptions() {
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
    if (!credential || credential.revokedAt !== null || !user || !responseHandle || !equalBytes(responseHandle, user.webAuthnUserHandle)) {
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
    const expiresAt = now + this.config.durations.sessionAbsoluteMs;
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
      credentialId: credential.id
    });
    await this.#emit({
      type: "session.created",
      at: now,
      userId: user.id,
      credentialId: credential.id
    });
    return {
      verified: true,
      sessionToken,
      expiresAt,
      credentialId: credential.id,
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
    const session = await this.#store.resolveSession(
      idHash,
      now,
      now - this.config.durations.sessionIdleMs
    );
    const user = session ? await this.#activeUser(session.userId) : null;
    if (!session || !user) {
      return null;
    }
    if (touch && !await this.#store.touchSession(idHash, now)) {
      return null;
    }
    return { user, session: { ...session, lastSeenAt: touch ? now : session.lastSeenAt } };
  }
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
  async revokeUserAuthentication(userId) {
    const now = this.#now();
    await this.#store.revokeUserAuthentication(userId, now);
    await this.#emit({ type: "user.authentication_revoked", at: now, userId });
  }
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
          authenticatedSessionHash: null
        };
      }
    } else if (input.sessionToken) {
      const authenticatedSessionHash = await sha256(input.sessionToken);
      const resolved = await this.resolveSession(input.sessionToken, false);
      if (resolved) {
        return {
          user: resolved.user,
          grantId: null,
          enrollmentSessionHash: null,
          authenticatedSessionHash
        };
      }
    }
    throw new LocalWebAuthnError(
      "enrollment_not_authorized",
      "A valid enrollment or authenticated session is required.",
      403
    );
  }
  async #verifyRegistrationAuthorization(challenge, input) {
    if (challenge.grantId && input.enrollmentSessionToken) {
      const enrollmentSessionHash = await sha256(input.enrollmentSessionToken);
      const enrollment = await this.#store.resolveEnrollmentSession(
        enrollmentSessionHash,
        this.#now()
      );
      return enrollment?.grantId === challenge.grantId ? { enrollmentSessionHash, authenticatedSessionHash: null } : null;
    }
    if (challenge.authorizationSessionHash && input.sessionToken) {
      const authenticatedSessionHash = await sha256(input.sessionToken);
      if (!equalBytes(authenticatedSessionHash, challenge.authorizationSessionHash)) {
        return null;
      }
      const session = await this.resolveSession(input.sessionToken, false);
      return session ? { enrollmentSessionHash: null, authenticatedSessionHash } : null;
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
  #credentialLabel(requestedLabel, deviceType) {
    const label = requestedLabel?.trim();
    if (label) {
      return label.slice(0, 80);
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
  createEnrollmentToken,
  createOpaqueToken,
  createUserHandle,
  decodeBase64Url,
  encodeBase32,
  encodeBase64Url,
  equalBytes,
  isLocalWebAuthnError,
  sha256
};
