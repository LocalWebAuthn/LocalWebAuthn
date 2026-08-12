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
  AuthenticationOptionsInput,
  AuthenticationOptionsResult,
  AuthenticationVerificationInput,
  AuthenticationVerificationResult,
  CeremonyProvider,
  Credential,
  EnrollmentExchange,
  EnrollmentIssue,
  LocalWebAuthnDpopStore,
  LocalWebAuthnEvent,
  LocalWebAuthnOptions,
  RegistrationOptionsInput,
  RegistrationOptionsResult,
  RegistrationVerificationInput,
  RegistrationVerificationResult,
  SessionIdentity,
} from './types.js';

import { kindPolicy, normalizeConfig } from './config.js';
import {
  createEnrollmentToken,
  createOpaqueToken,
  decodeBase64Url,
  defaultRandomBytes,
  equalBytes,
  sha256,
} from './crypto.js';
import { verifyDpopProof } from './dpop.js';
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
      /** The grant's declared kind, which overrides anything the route requests. */
      grantCredentialKind: string | null;
      /** Who approved the grant, copied onto the credential so it outlives the grant. */
      approvedByUserId: string | null;
      parentCredentialId: null;
    }
  | {
      user: AuthUser;
      grantId: null;
      enrollmentSessionHash: null;
      authenticatedSessionHash: Uint8Array;
      /** Always null: a session path has no grant to take a kind from. */
      grantCredentialKind: null;
      approvedByUserId: null;
      /** The credential whose session authorized this registration. */
      parentCredentialId: string;
    };

/** Normalize a host-supplied kind: trimmed, or `null` for unclassified. */
function normalizeKind(kind: string | undefined): string | null {
  const trimmed = kind?.trim() ?? '';
  return trimmed === '' ? null : trimmed;
}

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
   * @param options.approvedByUserId - ID of the administrator who approved this
   *   enrollment, recorded on the grant and on any credential it creates.
   * @param options.credentialKind - The {@link Credential.kind} this grant may
   *   create. Confines the token to that class: whichever route redeems it, the
   *   resulting credential gets this kind and its restrictions.
   * @returns The enrollment URL (with `#token=` fragment), raw token, expiry,
   *   and the IDs of any grants this issue superseded.
   */
  async issueEnrollment(
    userId: string,
    options: { approvedByUserId?: string; credentialKind?: string } = {},
  ): Promise<EnrollmentIssue> {
    const credentialKind = normalizeKind(options.credentialKind);
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
      approvedByUserId: options.approvedByUserId ?? null,
      credentialKind,
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
    const tokenHash = await sha256(token);
    const session = await this.#store.exchangeEnrollment(
      tokenHash,
      sessionHash,
      now + this.config.durations.enrollmentSessionMs,
      now,
    );
    if (!session) {
      throw await this.#refusedEnrollment(tokenHash, now);
    }

    const user = await this.#activeUser(session.userId);
    if (!user) {
      // Deliberately undiagnosed. The exchange *succeeded*, so this token's state
      // is now `used` — spent a moment ago by this very caller. Reporting that
      // would tell the rightful holder somebody else had beaten them to their own
      // link. The truth is only that the account is deactivated.
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
   * The error for an enrollment token the store would not consume, diagnosed as
   * far as the store allows.
   *
   * `exchangeEnrollment` answers `null` for five different situations, which is
   * correct for deciding and useless for explaining. This asks the store which one
   * it was, so a host can distinguish "somebody already used this link" — the one
   * case worth raising with the person holding it — from the ordinary "ask for a
   * new one".
   *
   * The status and code do not vary. A refused token is a refused token, and every
   * host that already handles `invalid_enrollment` keeps working unchanged; the
   * state rides along for hosts that want to say more.
   *
   * Emits `enrollment.rejected` so a host can act without touching the error at
   * all — notify every bound channel, raise a support signal, rate-limit a source.
   * A store with no `enrollmentGrantState` still emits state `unknown`, because "a
   * token was refused" is worth recording even undiagnosed. The thrown error keeps
   * its pre-diagnostics shape and has no `enrollmentState` in that case.
   */
  async #refusedEnrollment(tokenHash: Uint8Array, now: number): Promise<LocalWebAuthnError> {
    const diagnosed = this.#store.enrollmentGrantState
      ? await this.#store.enrollmentGrantState(tokenHash, now)
      : null;
    const rejection = diagnosed ?? {
      state: 'unknown' as const,
      userId: null,
    };
    await this.#emit({
      type: 'enrollment.rejected',
      at: now,
      state: rejection.state,
      userId: rejection.userId,
    });
    return new LocalWebAuthnError(
      'invalid_enrollment',
      rejection.state === 'used'
        ? 'This enrollment link has already been used.'
        : 'The enrollment link is invalid or expired.',
      403,
      diagnosed ? { enrollmentState: diagnosed.state } : {},
    );
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
  async registrationOptions(input: RegistrationOptionsInput): Promise<RegistrationOptionsResult> {
    const authorization = await this.#registrationAuthorization(input);
    const requested = normalizeKind(input.credentialKind);
    // On the grant path the kind belongs to the grant, written by whoever issued
    // it. It is binding: a token authorized for one class cannot be redeemed at a
    // route that asks for another, which is the confinement the column exists for.
    // A grant with no kind falls back to the route's, preserving the behaviour of
    // every host that does not set one.
    const granted = authorization.grantCredentialKind;
    if (granted !== null && requested !== null && granted !== requested) {
      throw new LocalWebAuthnError(
        'invalid_configuration',
        `This enrollment grant authorizes credential kind ${JSON.stringify(granted)}, ` +
          `but the route asked for ${JSON.stringify(requested)}.`,
        500,
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
        credentialKind,
        allowedCredentialKinds: null,
        // The registration fence. The credential insert re-checks this value, so a
        // revocation between here and `verifyRegistration` — a whole round trip
        // and a passkey ceremony away — cancels this registration instead of
        // racing it.
        registrationGeneration: await this.#store.registrationGeneration(
          authorization.user.id,
          now,
        ),
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
   * time) when the WebAuthn response does not verify. Unexpected storage
   * failures propagate as thrown errors rather than being misreported as an
   * expired authorization.
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
    const expiresAt = now + kindPolicy(this.config, challenge.credentialKind).sessionAbsoluteMs;
    const createdVia = authorization.grantId === null ? 'credential' : 'enrollment';
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
        createdVia,
        parentCredentialId: authorization.parentCredentialId,
        grantId: authorization.grantId,
        approvedByUserId: authorization.approvedByUserId,
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
      credentialKind: challenge.credentialKind,
      createdVia,
    });
    await this.#emit({
      type: 'session.created',
      at: now,
      userId: user.id,
      credentialId: credential.id,
      credentialKind: challenge.credentialKind,
    });
    return {
      verified: true,
      sessionToken,
      expiresAt,
      credentialId: credential.id,
      credentialKind: challenge.credentialKind,
    };
  }

  /**
   * Create discoverable-credential authentication options with
   * `userVerification: 'required'` and a single-use challenge token.
   *
   * No user is identified at this point; the authenticator chooses the
   * credential and {@link verifyAuthentication} resolves and checks the user.
   */
  async authenticationOptions(
    input: AuthenticationOptionsInput = {},
  ): Promise<AuthenticationOptionsResult> {
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
        credentialKind: null,
        allowedCredentialKinds: this.#admissibleKinds(input.credentialKinds),
        // Authentication creates no credential, so there is nothing to fence.
        registrationGeneration: null,
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
      !equalBytes(responseHandle, user.webAuthnUserHandle) ||
      // The ceremony declared which credential kinds it accepts, before this
      // client was handed a challenge. A machine credential presenting itself at
      // the browser sign-in route fails here, and vice versa — enforced once,
      // centrally, rather than in every host route.
      !this.#kindAdmitted(credential.kind, challenge.allowedCredentialKinds)
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
      credentialKind: credential.kind,
    });
    await this.#emit({
      type: 'session.created',
      at: now,
      userId: user.id,
      credentialId: credential.id,
      credentialKind: credential.kind,
    });
    return {
      verified: true,
      sessionToken,
      expiresAt,
      credentialId: credential.id,
      credentialKind: credential.kind,
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
  async revokeUserSessions(
    userId: string,
    options: { exceptSessionToken?: string; kinds?: (string | null)[] } = {},
  ): Promise<number> {
    const now = this.#now();
    const exceptHash = options.exceptSessionToken
      ? await sha256(options.exceptSessionToken)
      : undefined;

    // The same liveness cutoff `resolveSession` uses, on both paths: a session
    // this leaves alone must be one `resolveSession` would also refuse.
    const idleBefore = now - this.config.durations.sessionIdleMs;

    let count: number;
    if (options.kinds) {
      // Per credential, because a variable-length kind filter cannot be expressed
      // in the shared static SQL.
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
          idleBefore,
          exceptHash,
        );
      }
    } else {
      count = await this.#store.revokeUserSessions(userId, now, idleBefore, exceptHash);
    }

    if (count > 0) {
      await this.#emit({
        type: 'user.sessions_revoked',
        at: now,
        userId,
        count,
        ...(options.kinds ? { kinds: options.kinds } : {}),
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
  interactiveKind(kind: string | null): boolean {
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
  credentialLineage(userId: string, credentialId: string): Promise<Credential[]> {
    return this.#store.credentialAncestry(userId, credentialId);
  }

  /**
   * A credential and everything descended from it, nearest first.
   *
   * Index 0 is the credential itself. This is the blast radius of a compromised
   * credential: everything it was used to enroll, and everything those enrolled.
   */
  credentialDescendants(userId: string, credentialId: string): Promise<Credential[]> {
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
   * **Unscoped, this crosses kinds, and that is usually a surprise.** Every API
   * credential a person provisions has *their passkey* as its parent, so revoking
   * a suspected passkey's tree also stops their scripts. For a compromise that is
   * correct — the passkey could have minted those credentials, and after the fact
   * a legitimate one is indistinguishable from an attacker's. When it is not what
   * you meant, pass `kinds`.
   *
   * `kinds` restricts which credentials in the subtree are revoked; the walk is
   * unchanged. A credential excluded by `kinds` still has *its* descendants
   * considered, because the parent link records who enrolled whom regardless of
   * class — sparing a node must not silently spare what it created. `null` is a
   * legal member and matches unclassified credentials.
   *
   * @param options.kinds - Revoke only credentials of these {@link Credential.kind} values.
   * Re-enumerates until a pass revokes nothing, so a credential registered
   * *concurrently* with this call is caught rather than surviving a stale snapshot.
   * Unscoped, that is conclusive — every authority in the subtree is revoked, so
   * nothing remains that could author another. **With `kinds`, it is not:** a
   * spared credential still permitted to register can create a fresh in-scope
   * credential just after the final enumeration. Suspend registration for the user
   * (or deactivate them through `getUser`) while remediating a compromise.
   *
   * Throws `revocation_not_converged` (503) if credentials keep appearing until the
   * pass bound — remediation is then incomplete, and some credentials were revoked.
   *
   * @returns IDs actually revoked, root first. Already-revoked ones are skipped.
   */
  async revokeCredentialTree(
    userId: string,
    credentialId: string,
    options: { kinds?: (string | null)[] } = {},
  ): Promise<string[]> {
    const now = this.#now();
    const kinds = options.kinds ? new Set(options.kinds) : null;
    // `credentialDescendants` returns the root first, so the authority at the top
    // of the tree is revoked before the credentials beneath it.
    return this.#revokeCredentialsToFixedPoint(
      userId,
      now,
      () => this.#store.credentialDescendants(userId, credentialId),
      (credential) => !kinds || kinds.has(credential.kind),
      (credential) =>
        this.#emit({
          type: 'credential.revoked',
          at: now,
          userId,
          credentialId: credential.id,
          credentialKind: credential.kind,
        }),
    );
  }

  /**
   * Revoke every credential a re-read of `enumerate` yields that `select`
   * accepts, repeating until a pass revokes nothing.
   *
   * Re-enumeration, not a single snapshot, is what closes the remediation race. A
   * credential registered *after* the list is first read — by a live session
   * racing the revoke — would not be in that snapshot and would survive it.
   * Reading again after each pass catches it, and the store's conditional insert
   * (which requires the authorizing credential's `revoked_at IS NULL`) means a
   * revoked node can author no further children, so the frontier shrinks and the
   * loop converges — normally in two passes: one to revoke, one to confirm.
   *
   * **Two guarantees, and they differ.** When the operation revokes *every*
   * authority in scope — an unscoped tree, where the root and all its descendants
   * go — reaching a quiet pass is conclusive: nothing is left that could author a
   * new credential. When the caller *spares* authorities (a `kinds` filter, or a
   * scoped account revoke), a spared credential that is still permitted to
   * register can create a fresh in-scope credential right after the final
   * enumeration. Re-enumeration cannot fence that; only a registration epoch can,
   * and it is not implemented (docs/REVIEW-20260809.md §3). SECURITY.md states the
   * limit and tells hosts to suspend registration while remediating.
   *
   * Non-convergence is **not** reported as success: hitting the pass bound throws
   * `revocation_not_converged`, so a caller cannot mistake "credentials kept
   * appearing" for "remediation finished".
   */
  async #revokeCredentialsToFixedPoint(
    userId: string,
    now: number,
    enumerate: () => Promise<Credential[]>,
    select: (credential: Credential) => boolean,
    onRevoked?: (credential: Credential) => Promise<void>,
  ): Promise<string[]> {
    // Advance the fence before revoking anything. Every registration challenge
    // already issued to this user is now stale, so a ceremony in flight cannot
    // commit behind us — which is the half of the race that re-enumeration cannot
    // see, because the credential does not exist yet to be enumerated.
    await this.#store.bumpRegistrationGeneration(userId, now);

    const revoked: string[] = [];
    const seen = new Set<string>();
    const maxPasses = 64;
    for (let pass = 0; pass < maxPasses; pass += 1) {
      let progressed = false;
      for (const credential of await enumerate()) {
        if (credential.revokedAt !== null || seen.has(credential.id) || !select(credential)) {
          continue;
        }
        const result = await this.#store.revokeCredential(userId, credential.id, now, {
          allowLastCredential: true,
        });
        if (result === 'revoked') {
          progressed = true;
          seen.add(credential.id);
          revoked.push(credential.id);
          await onRevoked?.(credential);
        }
      }
      if (!progressed) {
        return revoked;
      }
    }
    // Still revoking on the last allowed pass: something is registering as fast as
    // this revokes. Fail loudly — a warning in a log is not an API contract, and a
    // caller responding to a compromise must not read this as "done".
    this.#logger.warn('Credential revocation did not converge; registrations may be racing it.', {
      userId,
      revoked: revoked.length,
    });
    throw new LocalWebAuthnError(
      'revocation_not_converged',
      `Revocation did not converge after ${String(maxPasses)} passes; ${String(revoked.length)} credentials were revoked. Suspend registration for this user and retry.`,
      503,
    );
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
    // Revoking one credential also invalidates registrations already authorized
    // for this user: the credential being removed may be the very authorizer a
    // pending ceremony is relying on.
    await this.#store.bumpRegistrationGeneration(userId, now);
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
   *
   * **The scoped form is administrative revocation, not complete remediation.** It
   * revokes to a fixed point, so a credential registered concurrently is caught
   * rather than missed — but it deliberately spares other kinds, and a spared
   * credential that may still register can create a fresh in-scope credential just
   * after the final enumeration. For a compromise, use the unscoped form (which
   * leaves no authority behind) and suspend the user while you do it. Throws
   * `revocation_not_converged` (503) if credentials keep appearing until the pass
   * bound; no `user.authentication_revoked` event is emitted in that case.
   */
  async revokeUserAuthentication(
    userId: string,
    options: { kinds?: (string | null)[] } = {},
  ): Promise<void> {
    const now = this.#now();
    if (options.kinds) {
      const kinds = new Set(options.kinds);
      // Close the grant path first. A live grant of a revoked kind is standing
      // authorization to create another credential of that kind, so a
      // grant-path registration started after this could otherwise re-enroll
      // straight back in.
      for (const kind of kinds) {
        for (const grantId of await this.#store.revokePendingEnrollmentGrants(userId, now, kind)) {
          await this.#emit({ type: 'enrollment.revoked', at: now, userId, grantId });
        }
      }
      // Then revoke the credentials of those kinds to a fixed point, so one
      // registered concurrently with this call is caught on re-enumeration
      // rather than surviving a single snapshot. `allowLastCredential` because a
      // scoped bulk revoke is a deliberate administrative act; the guard exists to
      // stop an *accidental* lockout via the single-credential path.
      await this.#revokeCredentialsToFixedPoint(
        userId,
        now,
        () => this.#store.listCredentials(userId, true),
        (credential) => kinds.has(credential.kind),
      );
    } else {
      await this.#store.bumpRegistrationGeneration(userId, now);
      await this.#store.revokeUserAuthentication(userId, now);
    }
    await this.#emit({
      type: 'user.authentication_revoked',
      at: now,
      userId,
      ...(options.kinds ? { kinds: options.kinds } : {}),
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
          grantCredentialKind: enrollment.credentialKind,
          approvedByUserId: enrollment.approvedByUserId,
          parentCredentialId: null,
        };
      }
    } else if (input.sessionToken) {
      const authenticatedSessionHash = await sha256(input.sessionToken);
      const resolved = await this.resolveSession(input.sessionToken, false);
      if (resolved) {
        // A machine credential may authenticate but may not enroll another
        // credential. Without this, a leaked machine key registers a spare and
        // survives revocation of the original, so revocation stops being a
        // remedy at all. This is the only place the check can live: nothing sits
        // between a host route and this call.
        if (!kindPolicy(this.config, resolved.session.credentialKind).canRegister) {
          throw new LocalWebAuthnError(
            'registration_not_permitted',
            'This credential may not register additional credentials.',
            403,
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
          parentCredentialId: resolved.session.credentialId,
        };
      }
    }

    throw new LocalWebAuthnError(
      'enrollment_not_authorized',
      'A valid enrollment or authenticated session is required.',
      403,
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
  #admissibleKinds(requested: (string | null)[] | undefined): (string | null)[] | null {
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
  #kindAdmitted(kind: string | null, allowed: (string | null)[] | null): boolean {
    return allowed === null ? kindPolicy(this.config, kind).interactive : allowed.includes(kind);
  }

  /**
   * The store, proved to implement {@link LocalWebAuthnDpopStore}.
   *
   * DPoP persistence is a separate contract because it serves an optional
   * feature, so the check is here, at the point of use, rather than in the
   * `store` type. A host that never issues API credentials writes none of these
   * methods; one that does and forgot gets told which are missing.
   */
  #dpopStore(): LocalWebAuthnDpopStore {
    const store = this.#store as Partial<LocalWebAuthnDpopStore>;
    const missing = (['claimDpopProof', 'claimDpopNonce', 'dpopNonces'] as const).filter(
      (method) => typeof store[method] !== 'function',
    );
    if (missing.length > 0) {
      throw new LocalWebAuthnError(
        'invalid_configuration',
        `DPoP needs a store implementing LocalWebAuthnDpopStore; missing ${missing.join(', ')}.`,
        500,
      );
    }
    return store as LocalWebAuthnDpopStore;
  }

  /** `floor(now / rotationMs)` — the same value on every server, from the clock alone. */
  #dpopSlot(now: number, rotationMs: number): number {
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
  async dpopNonce(): Promise<string | null> {
    if (!this.config.dpopNonce) {
      return null;
    }
    const { rotationMs } = this.config.dpopNonce;
    const now = this.#now();
    const slot = this.#dpopSlot(now, rotationMs);
    return this.#dpopStore().claimDpopNonce(
      slot,
      createOpaqueToken(this.#randomBytes),
      // Outlive the previous-slot grace window before becoming reapable.
      (slot + 3) * rotationMs,
    );
  }

  /** Current and previous slot, so a rotation mid-flight does not reject a fresh proof. */
  async #acceptableDpopNonces(now: number): Promise<string[]> {
    if (!this.config.dpopNonce) {
      return [];
    }
    const { rotationMs } = this.config.dpopNonce;
    const slot = this.#dpopSlot(now, rotationMs);
    // Claim the current slot first: a client cannot present a nonce for a slot no
    // server has issued yet, and this makes the current one exist even if the
    // deployment has served nothing since the slot turned over.
    const store = this.#dpopStore();
    await store.claimDpopNonce(slot, createOpaqueToken(this.#randomBytes), (slot + 3) * rotationMs);
    return store.dpopNonces(slot, slot - 1);
  }

  /**
   * Verify a DPoP proof (RFC 9449) for a request on an already-resolved session.
   *
   * **Prefer {@link authenticateMachineRequest} for a machine route.** This is
   * the lower-level primitive: it trusts the caller to have resolved `session`
   * from `sessionToken` and to touch the session only after this succeeds. Pair a
   * token with the wrong session, or resolve-with-touch before calling this, and
   * the sender-constraint guarantee is lost. `authenticateMachineRequest` removes
   * both footguns by taking only the token.
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
  async verifyDpop(input: {
    proof: string | undefined;
    method: string;
    url: string;
    sessionToken: string;
    session: SessionIdentity;
    /**
     * Demand a server-issued nonce (RFC 9449 section 8). Requires `dpopNonce` in
     * configuration; throws `dpop_nonce_required` when the proof carries none or
     * carries one the server no longer recognises.
     */
    requireNonce?: boolean;
  }): Promise<void> {
    if (!input.proof) {
      throw new LocalWebAuthnError('invalid_dpop_proof', 'A DPoP proof is required.', 401);
    }
    // Before any verification work, so a store missing the DPoP contract is
    // reported as the configuration error it is, whether or not the proof is good.
    const dpopStore = this.#dpopStore();
    if (input.requireNonce && !this.config.dpopNonce) {
      throw new LocalWebAuthnError(
        'invalid_configuration',
        'requireNonce needs dpopNonce configuration; otherwise no nonce is ever issued.',
        500,
      );
    }
    const credential = await this.#store.getCredential(input.session.credentialId);
    if (!credential || credential.revokedAt !== null) {
      throw new LocalWebAuthnError('invalid_dpop_proof', 'The credential is unavailable.', 401);
    }

    const now = this.#now();
    const verification = await verifyDpopProof({
      proof: input.proof,
      method: input.method,
      url: input.url,
      accessToken: input.sessionToken,
      publicKeyCose: credential.publicKey,
      nonces: input.requireNonce ? await this.#acceptableDpopNonces(now) : undefined,
      now,
    });
    if (!verification.valid) {
      // A nonce problem gets its own code so the host knows to answer with a
      // `use_dpop_nonce` challenge and a fresh header, rather than a flat refusal.
      throw new LocalWebAuthnError(
        verification.reason === 'use_dpop_nonce' ? 'dpop_nonce_required' : 'invalid_dpop_proof',
        `The DPoP proof is not valid (${verification.reason}).`,
        401,
      );
    }
    if (!(await dpopStore.claimDpopProof(verification.jtiHash, verification.expiresAt))) {
      throw new LocalWebAuthnError(
        'invalid_dpop_proof',
        'The DPoP proof is not valid (replayed).',
        401,
      );
    }
  }

  /**
   * Resolve a machine request's session **only if** its DPoP proof holds — one
   * fail-closed operation for a sender-constrained (RFC 9449) route.
   *
   * This is the method a machine route should call. It closes two gaps that come
   * from assembling {@link resolveSession} and {@link verifyDpop} by hand:
   *
   * - **The session is derived from the token, never supplied alongside it.** A
   *   caller cannot pair a token for one session with the resolved identity of
   *   another, because there is only one input.
   * - **Idle activity is touched only after the proof succeeds.** Resolving first
   *   with `touch` would let a thief holding just the bearer token keep the idle
   *   timer alive to absolute expiry without ever producing a proof. Here a
   *   request that cannot prove possession changes no server state.
   *
   * A DPoP proof is always required; there is no bearer-only path through this
   * method. Throws `unauthenticated` (401) when the token resolves to no live
   * session, `dpop_nonce_required` (401) when a nonce is demanded and absent
   * (answer with {@link dpopChallenge}), and `invalid_dpop_proof` (401) on any
   * other proof failure. On success the session's `lastSeenAt` is advanced.
   *
   * @returns The authenticated user and session, plus the current response nonce
   *   (`null` when nonce issuance is not configured).
   */
  async authenticateMachineRequest(input: {
    sessionToken: string;
    proof: string | undefined;
    method: string;
    url: string;
    /** Demand a server-issued nonce (RFC 9449 section 8). Requires `dpopNonce`. */
    requireNonce?: boolean;
  }): Promise<{ user: AuthUser; session: SessionIdentity; nonce: string | null }> {
    // No touch: a request that fails the proof below must not have refreshed the
    // session's activity.
    const resolved = await this.resolveSession(input.sessionToken, false);
    if (!resolved) {
      throw new LocalWebAuthnError('unauthenticated', 'An API session is required.', 401);
    }

    // Verifies the proof against the credential of *this* session and binds it to
    // *this* token; a mismatch is impossible because both come from one input.
    await this.verifyDpop({
      proof: input.proof,
      method: input.method,
      url: input.url,
      sessionToken: input.sessionToken,
      session: resolved.session,
      requireNonce: input.requireNonce,
    });

    // Proof held: now, and only now, keep the session alive.
    const now = this.#now();
    if (!(await this.#store.touchSession(await sha256(input.sessionToken), now))) {
      // A concurrent revoke landed between resolution and this update.
      throw new LocalWebAuthnError('unauthenticated', 'An API session is required.', 401);
    }

    return {
      user: resolved.user,
      session: { ...resolved.session, lastSeenAt: now },
      nonce: await this.dpopNonce(),
    };
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
    /** Non-null on the grant path; the credential's recorded heritage. */
    grantId: string | null;
    approvedByUserId: string | null;
    /** Non-null on the session path; the credential that authorized this one. */
    parentCredentialId: string | null;
  } | null> {
    if (challenge.grantId && input.enrollmentSessionToken) {
      const enrollmentSessionHash = await sha256(input.enrollmentSessionToken);
      const enrollment = await this.#store.resolveEnrollmentSession(
        enrollmentSessionHash,
        this.#now(),
      );
      return enrollment?.grantId === challenge.grantId
        ? {
            enrollmentSessionHash,
            authenticatedSessionHash: null,
            grantId: enrollment.grantId,
            approvedByUserId: enrollment.approvedByUserId,
            parentCredentialId: null,
          }
        : null;
    }

    if (challenge.authorizationSessionHash && input.sessionToken) {
      const authenticatedSessionHash = await sha256(input.sessionToken);
      if (!equalBytes(authenticatedSessionHash, challenge.authorizationSessionHash)) {
        return null;
      }
      const session = await this.resolveSession(input.sessionToken, false);
      return session
        ? {
            enrollmentSessionHash: null,
            authenticatedSessionHash,
            grantId: null,
            approvedByUserId: null,
            // Re-read here rather than carried from `registrationOptions`: this is
            // the session that still holds at commit time, which is the one that
            // actually authorized the credential.
            parentCredentialId: session.session.credentialId,
          }
        : null;
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
    kind: string | null,
  ): string {
    const label = requestedLabel?.trim();
    if (label) {
      return label.slice(0, 80);
    }
    // "Device passkey" on a machine credential is the mislabelling this whole
    // feature exists to prevent, so a kinded credential falls back to its kind
    // rather than to device wording it cannot honestly claim.
    if (kind !== null) {
      return kind.slice(0, 80);
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
