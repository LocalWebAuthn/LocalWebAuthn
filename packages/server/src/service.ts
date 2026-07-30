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

export class LocalWebAuthn {
  readonly config;

  readonly #store;
  readonly #users;
  readonly #now;
  readonly #randomBytes;
  readonly #ceremonies;
  readonly #onEvent;

  constructor(options: LocalWebAuthnOptions) {
    this.config = normalizeConfig(options);
    this.#store = options.store;
    this.#users = options.users;
    this.#now = options.now ?? Date.now;
    this.#randomBytes = options.randomBytes ?? defaultRandomBytes;
    this.#ceremonies = options.ceremonies ?? defaultCeremonies;
    this.#onEvent = options.onEvent;
  }

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
    };
  }

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
    await this.#store.createChallenge({
      idHash: await sha256(challengeToken),
      kind: 'registration',
      challenge: options.challenge,
      userId: authorization.user.id,
      grantId: authorization.grantId,
      authorizationSessionHash: authorization.authenticatedSessionHash,
      expiresAt,
      createdAt: now,
    });
    return { options, challengeToken, expiresAt };
  }

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

  async authenticationOptions(): Promise<AuthenticationOptionsResult> {
    const options = await this.#ceremonies.generateAuthenticationOptions({
      rpID: this.config.rpId,
      userVerification: 'required',
    });
    const now = this.#now();
    const challengeToken = createOpaqueToken(this.#randomBytes);
    const expiresAt = now + this.config.durations.challengeMs;
    await this.#store.createChallenge({
      idHash: await sha256(challengeToken),
      kind: 'authentication',
      challenge: options.challenge,
      userId: null,
      grantId: null,
      authorizationSessionHash: null,
      expiresAt,
      createdAt: now,
    });
    return { options, challengeToken, expiresAt };
  }

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

    const sessionToken = createOpaqueToken(this.#randomBytes);
    const expiresAt = now + this.config.durations.sessionAbsoluteMs;
    const completed = await this.#store.completeAuthentication({
      credentialId: credential.id,
      previousCounter: credential.counter,
      newCounter: verification.authenticationInfo.newCounter,
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

  async revokeSession(sessionToken: string): Promise<boolean> {
    const now = this.#now();
    const revoked = await this.#store.revokeSession(await sha256(sessionToken), now);
    if (revoked) {
      await this.#emit({ type: 'session.revoked', at: now });
    }
    return revoked;
  }

  listCredentials(userId: string, includeRevoked = false): Promise<Credential[]> {
    return this.#store.listCredentials(userId, includeRevoked);
  }

  async revokeCredential(
    userId: string,
    credentialId: string,
    options: { allowLastCredential?: boolean } = {},
  ): Promise<boolean> {
    if (!options.allowLastCredential) {
      const credentials = await this.#store.listCredentials(userId);
      if (credentials.length <= 1 && credentials.some(({ id }) => id === credentialId)) {
        throw new LocalWebAuthnError(
          'last_credential',
          'The final active credential cannot be revoked without a recovery flow.',
          409,
        );
      }
    }

    const now = this.#now();
    const revoked = await this.#store.revokeCredential(userId, credentialId, now);
    if (revoked) {
      await this.#emit({
        type: 'credential.revoked',
        at: now,
        userId,
        credentialId,
      });
    }
    return revoked;
  }

  revokeUserAuthentication(userId: string): Promise<void> {
    return this.#store.revokeUserAuthentication(userId, this.#now());
  }

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
    } catch {
      // Authentication has already committed; observational hooks cannot roll it back.
    }
  }
}

export type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
};
