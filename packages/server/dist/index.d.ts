import { h as LocalWebAuthnOptions, i as EnrollmentIssue, j as EnrollmentExchange, R as RegistrationOptionsResult, k as RegistrationVerificationInput, l as RegistrationVerificationResult, A as AuthenticationOptionsResult, m as AuthenticationVerificationInput, n as AuthenticationVerificationResult, o as AuthUser, S as SessionIdentity, d as Credential, g as CleanupResult } from './types-TH3Ore5_.js';
export { p as CeremonyProvider, b as ChallengeKind, C as ChallengeRecord, f as CompleteAuthenticationInput, e as CompleteRegistrationInput, c as ConsumedChallenge, E as EnrollmentGrantRecord, a as EnrollmentSession, q as LocalWebAuthnDurations, r as LocalWebAuthnEvent, L as LocalWebAuthnStore, N as NewCredential, s as NewSession, U as UserProvider } from './types-TH3Ore5_.js';
export { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';

declare function defaultRandomBytes(length: number): Uint8Array;
declare function sha256(value: string | Uint8Array): Promise<Uint8Array>;
declare function encodeBase32(bytes: Uint8Array): string;
declare function encodeBase64Url(bytes: Uint8Array): string;
declare function decodeBase64Url(value: string): Uint8Array | null;
declare function equalBytes(left: Uint8Array, right: Uint8Array): boolean;
declare function createUserHandle(randomBytes?: typeof defaultRandomBytes): Uint8Array;
declare function createEnrollmentToken(randomBytes?: typeof defaultRandomBytes): string;
declare function createOpaqueToken(randomBytes?: typeof defaultRandomBytes): string;

type LocalWebAuthnErrorCode = 'invalid_configuration' | 'invalid_enrollment' | 'enrollment_not_authorized' | 'invalid_ceremony' | 'registration_failed' | 'authentication_failed' | 'unauthenticated' | 'credential_not_found' | 'last_credential';
declare class LocalWebAuthnError extends Error {
    readonly code: LocalWebAuthnErrorCode;
    readonly status: number;
    constructor(code: LocalWebAuthnErrorCode, message: string, status: number);
}
declare function isLocalWebAuthnError(value: unknown): value is LocalWebAuthnError;

type NormalizedConfig = {
    rpName: string;
    rpId: string;
    expectedOrigins: string[];
    publicOrigin: string;
    enrollmentPath: string;
    durations: {
        enrollmentGrantMs: number;
        enrollmentSessionMs: number;
        challengeMs: number;
        sessionIdleMs: number;
        sessionAbsoluteMs: number;
    };
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
declare class LocalWebAuthn {
    #private;
    /** Normalized configuration (see {@link LocalWebAuthnOptions}). */
    readonly config: NormalizedConfig;
    constructor(options: LocalWebAuthnOptions);
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
    issueEnrollment(userId: string, approvedByUserId?: string): Promise<EnrollmentIssue>;
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
    exchangeEnrollment(enrollmentToken: string): Promise<EnrollmentExchange>;
    registrationOptions(input: {
        enrollmentSessionToken?: string;
        sessionToken?: string;
    }): Promise<RegistrationOptionsResult>;
    verifyRegistration(input: RegistrationVerificationInput): Promise<RegistrationVerificationResult>;
    authenticationOptions(): Promise<AuthenticationOptionsResult>;
    verifyAuthentication(input: AuthenticationVerificationInput): Promise<AuthenticationVerificationResult>;
    /**
     * Resolve a session token to a user and session identity.
     *
     * Returns `null` if the session is expired, idle, revoked, the credential was
     * revoked, or the user is inactive.
     *
     * @param sessionToken - The raw opaque session token (from cookie).
     * @param touch - When `true` (default), update `lastSeenAt` to keep the session alive.
     */
    resolveSession(sessionToken: string, touch?: boolean): Promise<{
        user: AuthUser;
        session: SessionIdentity;
    } | null>;
    revokeSession(sessionToken: string): Promise<boolean>;
    listCredentials(userId: string, includeRevoked?: boolean): Promise<Credential[]>;
    /**
     * Revoke a single credential and all its sessions.
     *
     * Throws {@link LocalWebAuthnError} with code `"last_credential"` if this is
     * the user's only remaining active credential. Pass `{ allowLastCredential: true }`
     * to override this safeguard (e.g., during a recovery flow).
     *
     * @returns `true` if the credential was revoked, `false` if it was already revoked.
     */
    revokeCredential(userId: string, credentialId: string, options?: {
        allowLastCredential?: boolean;
    }): Promise<boolean>;
    revokeUserAuthentication(userId: string): Promise<void>;
    cleanup(): Promise<CleanupResult>;
}

export { AuthUser, AuthenticationOptionsResult, AuthenticationVerificationInput, AuthenticationVerificationResult, CleanupResult, Credential, EnrollmentExchange, EnrollmentIssue, LocalWebAuthn, LocalWebAuthnError, type LocalWebAuthnErrorCode, LocalWebAuthnOptions, RegistrationOptionsResult, RegistrationVerificationInput, RegistrationVerificationResult, SessionIdentity, createEnrollmentToken, createOpaqueToken, createUserHandle, decodeBase64Url, encodeBase32, encodeBase64Url, equalBytes, isLocalWebAuthnError, sha256 };
