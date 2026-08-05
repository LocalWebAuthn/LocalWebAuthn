import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';

import type {
  AuthUser,
  AuthenticationOptionsResult,
  AuthenticationVerificationInput,
  AuthenticationVerificationResult,
  CeremonyProvider,
  Credential,
  EnrollmentExchange,
  EnrollmentIssue,
  LocalWebAuthnEvent,
  LocalWebAuthnOptions,
  RegistrationOptionsResult,
  RegistrationVerificationInput,
  RegistrationVerificationResult,
  SessionIdentity,
} from './types.js';

import { normalizeConfig } from './config.js';
import {
  createEnrollmentToken,
  createOpaqueToken,
  decodeBase64Url,
  defaultRandomBytes,
  equalBytes,
  sha256,
} from './crypto.js';
import { LocalWebAuthnError } from './errors.js';
import { toWebAuthnCredential } from './types.js';

const defaultCeremonies: CeremonyProvider = {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
};

type RegistrationAuthorization =
  | {
      user: AuthUser;
      grantId: string;
      enrollmentSessionHash: Uint8Array;
      authenticatedSessionHash: null;
    }
  | {
      user: AuthUser;
      grantId: null;
      enrollmentSessionHash: null;
      authenticatedSessionHash: Uint8Array;
    };

/**
 * Framework-neutral passkey authentication lifecycle.
 *
 * Owns enrollment grants, registration and authentication challenges,
 * credential metadata and counters, opaque sessions, and revocation.
 * Delegates WebAuthn cryptographic ceremonies to `@simplewebauthn/server`
 * (or a provided {@link CeremonyProvider}).
 *
 * The host application retains its own user directory and provides a
 * {@link UserProvider} for user lookup. It also owns HTTP concerns
 * (cookies, origins, CSRF, rate limiting) and identity proofing.
 *
 * ```ts
 * const auth = new LocalWebAuthn({
 *   rpName: 'My App',
 *   rpId: 'app.example.com',
 *   expectedOrigins: 'https://app.example.com',
 *   store: new SqliteLocalWebAuthnStore(database),
 *   users: { getUser: async (id) => appUsers.get(id) },
 * });
 * ```
 */
export class LocalWebAuthn {
  /** Normalized configuration (see {@link LocalWebAuthnOptions}). */
  readonly config;

  readonly #store;
  readonly #users;
  readonly #now;
  readonly #randomBytes;
  readonly #ceremonies;
  readonly #onEvent;
  readonly #logger;

  constructor(options: LocalWebAuthnOptions) {
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
  async issueEnrollment(userId: string, approvedByUserId?: string): Promise<EnrollmentIssue> {
    const user = await this.#activeUser(userId);
    if (!user) {
      throw new LocalWebAuthnError(
        'invalid_enrollment',
        'Enrollment cannot be issued for this user.',
        404,
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
      createdAt: now,
    });

    for (const revokedGrantId of revokedGrantIds) {
      await this.#emit({
        type: 'enrollment.revoked',
        at: now,
        userId,
        grantId: revokedGrantId,
      });
    }

    const enrollmentUrl = new URL(this.config.enrollmentPath, this.config.publicOrigin);
    enrollmentUrl.hash = `token=${enrollmentToken}`;
    await this.#emit({ type: 'enrollment.issued', at: now, userId, grantId });
    return {
      grantId,
      enrollmentToken,
      enrollmentUrl: enrollmentUrl.toString(),
      expiresAt,
      supersededGrantIds: revokedGrantIds,
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
  async exchangeEnrollment(enrollmentToken: string): Promise<EnrollmentExchange> {
    const token = enrollmentToken.toLowerCase();
    if (!/^[a-z2-7]{52}$/u.test(token)) {
      throw new LocalWebAuthnError('invalid_enrollment', 'The enrollment link is invalid.', 400);
    }

    const now = this.#now();
    const enrollmentSessionToken = createOpaqueToken(this.#randomBytes);
    const sessionHash = await sha256(enrollmentSessionToken);
    const session = await this.#store.exchangeEnrollment(
      await sha256(token),
      sessionHash,
      now + this.config.durations.enrollmentSessionMs,
      now,
    );
    const user = session ? await this.#activeUser(session.userId) : null;
    if (!session || !user) {
      throw new LocalWebAuthnError(
        'invalid_enrollment',
        'The enrollment link is invalid or expired.',
        403,
      );
    }

    await this.#emit({
      type: 'enrollment.exchanged',
      at: now,
      userId: user.id,
      grantId: session.grantId,
    });
    return {
      enrollmentSessionToken,
      expiresAt: session.sessionExpiresAt,
      user: this.#publicUser(user),
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
  async registrationOptions(input: {
    enrollmentSessionToken?: string;
    sessionToken?: string;
  }): Promise<RegistrationOptionsResult> {
    const authorization = await this.#registrationAuthorization(input);
    const credentials = await this.#store.listCredentials(authorization.user.id);
    const options = await this.#ceremonies.generateRegistrationOptions({
      rpName: this.config.rpName,
      rpID: this.config.rpId,
      userID: Uint8Array.from(authorization.user.webAuthnUserHandle),
      userName: authorization.user.name,
      userDisplayName: authorization.user.displayName,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
      excludeCredentials: credentials.map((credential) => ({
        id: credential.id,
        transports: credential.transports,
      })),
    });

    const now = this.#now();
    const challengeToken = createOpaqueToken(this.#randomBytes);
    const expiresAt = now + this.config.durations.challengeMs;
    if (
      !(await this.#store.createChallenge({
        idHash: await sha256(challengeToken),
        kind: 'registration',
        challenge: options.challenge,
        userId: authorization.user.id,
        grantId: authorization.grantId,
        authorizationSessionHash: authorization.authenticatedSessionHash,
        expiresAt,
        createdAt: now,
      }))
    ) {
      throw new LocalWebAuthnError(
        'invalid_ceremony',
        'A challenge token collision occurred; retry the ceremony.',
        409,
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
   * time) when the WebAuthn response does not verify.
   */
  async verifyRegistration(
    input: RegistrationVerificationInput,
  ): Promise<RegistrationVerificationResult> {
    const now = this.#now();
    const challenge = await this.#store.consumeChallenge(
      await sha256(input.challengeToken),
      'registration',
      now,
    );
    if (!challenge?.userId) {
      throw new LocalWebAuthnError(
        'invalid_ceremony',
        'The registration ceremony is invalid or expired.',
        400,
      );
    }

    const authorization = await this.#verifyRegistrationAuthorization(challenge, input);
    const user = await this.#activeUser(challenge.userId);
    if (!authorization || !user) {
      throw new LocalWebAuthnError(
        'enrollment_not_authorized',
        'A valid enrollment or authenticated session is required.',
        403,
      );
    }

    let verification;
    try {
      verification = await this.#ceremonies.verifyRegistrationResponse({
        response: input.response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: this.config.expectedOrigins,
        expectedRPID: this.config.rpId,
        requireUserVerification: true,
      });
    } catch {
      throw new LocalWebAuthnError(
        'registration_failed',
        'The passkey could not be verified.',
        400,
      );
    }

    if (!verification.verified) {
      throw new LocalWebAuthnError(
        'registration_failed',
        'The passkey could not be verified.',
        400,
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
        createdAt: now,
      },
      session: {
        idHash: await sha256(sessionToken),
        userId: user.id,
        credentialId: credential.id,
        authenticatedAt: now,
        expiresAt,
        lastSeenAt: now,
      },
      now,
    });
    if (!completed) {
      throw new LocalWebAuthnError(
        'registration_failed',
        'The registration authorization is no longer valid.',
        409,
      );
    }

    if (challenge.grantId) {
      await this.#emit({
        type: 'enrollment.completed',
        at: now,
        userId: user.id,
        grantId: challenge.grantId,
      });
    }
    await this.#emit({
      type: 'credential.registered',
      at: now,
      userId: user.id,
      credentialId: credential.id,
    });
    await this.#emit({
      type: 'session.created',
      at: now,
      userId: user.id,
      credentialId: credential.id,
    });
    return { verified: true, sessionToken, expiresAt, credentialId: credential.id };
  }

  /**
   * Create discoverable-credential authentication options with
   * `userVerification: 'required'` and a single-use challenge token.
   *
   * No user is identified at this point; the authenticator chooses the
   * credential and {@link verifyAuthentication} resolves and checks the user.
   */
  async authenticationOptions(): Promise<AuthenticationOptionsResult> {
    const options = await this.#ceremonies.generateAuthenticationOptions({
      rpID: this.config.rpId,
      userVerification: 'required',
    });
    const now = this.#now();
    const challengeToken = createOpaqueToken(this.#randomBytes);
    const expiresAt = now + this.config.durations.challengeMs;
    if (
      !(await this.#store.createChallenge({
        idHash: await sha256(challengeToken),
        kind: 'authentication',
        challenge: options.challenge,
        userId: null,
        grantId: null,
        authorizationSessionHash: null,
        expiresAt,
        createdAt: now,
      }))
    ) {
      throw new LocalWebAuthnError(
        'invalid_ceremony',
        'A challenge token collision occurred; retry the ceremony.',
        409,
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
  async verifyAuthentication(
    input: AuthenticationVerificationInput,
  ): Promise<AuthenticationVerificationResult> {
    const now = this.#now();
    const challenge = await this.#store.consumeChallenge(
      await sha256(input.challengeToken),
      'authentication',
      now,
    );
    if (!challenge) {
      throw new LocalWebAuthnError(
        'invalid_ceremony',
        'The authentication ceremony is invalid or expired.',
        400,
      );
    }

    const credential = await this.#store.getCredential(input.response.id);
    const user = credential ? await this.#activeUser(credential.userId) : null;
    const responseHandle = input.response.response.userHandle
      ? decodeBase64Url(input.response.response.userHandle)
      : null;
    if (
      !credential ||
      credential.revokedAt !== null ||
      !user ||
      !responseHandle ||
      !equalBytes(responseHandle, user.webAuthnUserHandle)
    ) {
      throw new LocalWebAuthnError(
        'authentication_failed',
        'The passkey could not be verified.',
        401,
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
        requireUserVerification: true,
      });
    } catch {
      throw new LocalWebAuthnError(
        'authentication_failed',
        'The passkey could not be verified.',
        401,
      );
    }

    if (!verification.verified) {
      throw new LocalWebAuthnError(
        'authentication_failed',
        'The passkey could not be verified.',
        401,
      );
    }

    const previousCounter = credential.counter;
    const newCounter = verification.authenticationInfo.newCounter;
    // WebAuthn: non-zero counters must strictly increase; 0→0 is allowed.
    if ((previousCounter > 0 || newCounter > 0) && newCounter <= previousCounter) {
      throw new LocalWebAuthnError(
        'authentication_failed',
        'The passkey could not be verified.',
        401,
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
        lastSeenAt: now,
      },
      now,
    });
    if (!completed) {
      throw new LocalWebAuthnError(
        'authentication_failed',
        'The passkey changed during authentication.',
        409,
      );
    }

    await this.#emit({
      type: 'credential.authenticated',
      at: now,
      userId: user.id,
      credentialId: credential.id,
    });
    await this.#emit({
      type: 'session.created',
      at: now,
      userId: user.id,
      credentialId: credential.id,
    });
    return {
      verified: true,
      sessionToken,
      expiresAt,
      credentialId: credential.id,
      user: this.#publicUser(user),
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
  async resolveSession(
    sessionToken: string,
    touch = true,
  ): Promise<{
    user: AuthUser;
    session: SessionIdentity;
  } | null> {
    const idHash = await sha256(sessionToken);
    const now = this.#now();
    const session = await this.#store.resolveSession(
      idHash,
      now,
      now - this.config.durations.sessionIdleMs,
    );
    const user = session ? await this.#activeUser(session.userId) : null;
    if (!session || !user) {
      return null;
    }
    if (touch && !(await this.#store.touchSession(idHash, now))) {
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
  async revokeSession(sessionToken: string): Promise<boolean> {
    const now = this.#now();
    const revoked = await this.#store.revokeSession(await sha256(sessionToken), now);
    if (revoked) {
      await this.#emit({
        type: 'session.revoked',
        at: now,
        userId: revoked.userId,
        credentialId: revoked.credentialId,
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
   * @param userId - The application user whose sessions end.
   * @param options.exceptSessionToken - Raw session token to leave live.
   * @returns The number of live sessions revoked.
   */
  async revokeUserSessions(
    userId: string,
    options: { exceptSessionToken?: string } = {},
  ): Promise<number> {
    const now = this.#now();
    const count = await this.#store.revokeUserSessions(
      userId,
      now,
      now - this.config.durations.sessionIdleMs,
      options.exceptSessionToken ? await sha256(options.exceptSessionToken) : undefined,
    );
    if (count > 0) {
      await this.#emit({ type: 'user.sessions_revoked', at: now, userId, count });
    }
    return count;
  }

  /** List a user's credentials; revoked ones only when `includeRevoked` is `true`. */
  listCredentials(userId: string, includeRevoked = false): Promise<Credential[]> {
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
  async revokeCredential(
    userId: string,
    credentialId: string,
    options: { allowLastCredential?: boolean } = {},
  ): Promise<boolean> {
    const now = this.#now();
    // Last-credential protection is enforced atomically inside the store so two
    // concurrent revokes cannot both observe "more than one active" and empty
    // the account.
    const result = await this.#store.revokeCredential(userId, credentialId, now, options);
    if (result === 'last_credential') {
      throw new LocalWebAuthnError(
        'last_credential',
        'The final active credential cannot be revoked without a recovery flow.',
        409,
      );
    }
    if (result === 'revoked') {
      await this.#emit({
        type: 'credential.revoked',
        at: now,
        userId,
        credentialId,
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
   */
  async revokeUserAuthentication(userId: string): Promise<void> {
    const now = this.#now();
    await this.#store.revokeUserAuthentication(userId, now);
    await this.#emit({ type: 'user.authentication_revoked', at: now, userId });
  }

  /**
   * Reap expired enrollment grants, finished challenges, and dead sessions.
   * Schedule periodically (every few minutes is ample); credentials are never
   * part of cleanup.
   */
  cleanup() {
    return this.#store.cleanup(this.#now());
  }

  async #registrationAuthorization(input: {
    enrollmentSessionToken?: string;
    sessionToken?: string;
  }): Promise<RegistrationAuthorization> {
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
          authenticatedSessionHash,
        };
      }
    }

    throw new LocalWebAuthnError(
      'enrollment_not_authorized',
      'A valid enrollment or authenticated session is required.',
      403,
    );
  }

  async #verifyRegistrationAuthorization(
    challenge: {
      grantId: string | null;
      authorizationSessionHash: Uint8Array | null;
    },
    input: RegistrationVerificationInput,
  ): Promise<{
    enrollmentSessionHash: Uint8Array | null;
    authenticatedSessionHash: Uint8Array | null;
  } | null> {
    if (challenge.grantId && input.enrollmentSessionToken) {
      const enrollmentSessionHash = await sha256(input.enrollmentSessionToken);
      const enrollment = await this.#store.resolveEnrollmentSession(
        enrollmentSessionHash,
        this.#now(),
      );
      return enrollment?.grantId === challenge.grantId
        ? { enrollmentSessionHash, authenticatedSessionHash: null }
        : null;
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

  async #activeUser(userId: string): Promise<AuthUser | null> {
    const user = await this.#users.getUser(userId);
    return user?.active && user.webAuthnUserHandle.length === 32 ? user : null;
  }

  #publicUser(user: AuthUser): Pick<AuthUser, 'id' | 'name' | 'displayName'> {
    return { id: user.id, name: user.name, displayName: user.displayName };
  }

  #credentialLabel(
    requestedLabel: string | undefined,
    deviceType: 'singleDevice' | 'multiDevice',
  ): string {
    const label = requestedLabel?.trim();
    if (label) {
      return label.slice(0, 80);
    }
    return deviceType === 'multiDevice' ? 'Synced passkey' : 'Device passkey';
  }

  async #emit(event: LocalWebAuthnEvent): Promise<void> {
    if (!this.#onEvent) {
      return;
    }
    try {
      await this.#onEvent(event);
    } catch (error) {
      // Authentication has already committed; observational hooks cannot roll it back.
      this.#logger.warn('LocalWebAuthn event handler failed.', { event: event.type, error });
    }
  }
}

export type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
};
