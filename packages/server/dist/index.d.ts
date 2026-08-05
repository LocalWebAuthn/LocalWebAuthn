import { i as LocalWebAuthnOptions, j as EnrollmentIssue, k as EnrollmentExchange, l as RegistrationOptionsResult, m as RegistrationVerificationInput, n as RegistrationVerificationResult, A as AuthenticationOptionsResult, o as AuthenticationVerificationInput, p as AuthenticationVerificationResult, q as AuthUser, S as SessionIdentity, d as Credential, h as CleanupResult } from './types-CDh1Rr6m.js';
export { r as CeremonyProvider, b as ChallengeKind, C as ChallengeRecord, f as CompleteAuthenticationInput, e as CompleteRegistrationInput, c as ConsumedChallenge, E as EnrollmentGrantRecord, a as EnrollmentSession, s as LocalWebAuthnDurations, t as LocalWebAuthnEvent, L as LocalWebAuthnStore, N as NewCredential, u as NewSession, g as RevokeCredentialResult, R as RevokedSession, U as UserProvider } from './types-CDh1Rr6m.js';
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
    issueEnrollment(userId: string, approvedByUserId?: string): Promise<EnrollmentIssue>;
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
    exchangeEnrollment(enrollmentToken: string): Promise<EnrollmentExchange>;
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
    registrationOptions(input: {
        enrollmentSessionToken?: string;
        sessionToken?: string;
    }): Promise<RegistrationOptionsResult>;
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
    verifyRegistration(input: RegistrationVerificationInput): Promise<RegistrationVerificationResult>;
    /**
     * Create discoverable-credential authentication options with
     * `userVerification: 'required'` and a single-use challenge token.
     *
     * No user is identified at this point; the authenticator chooses the
     * credential and {@link verifyAuthentication} resolves and checks the user.
     */
    authenticationOptions(): Promise<AuthenticationOptionsResult>;
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
    /**
     * Revoke a single session by its raw token (logout).
     *
     * @returns `true` if a live session was revoked, `false` if the token was
     *   unknown or already revoked.
     */
    revokeSession(sessionToken: string): Promise<boolean>;
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
    revokeUserSessions(userId: string, options?: {
        exceptSessionToken?: string;
    }): Promise<number>;
    /** List a user's credentials; revoked ones only when `includeRevoked` is `true`. */
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
    /**
     * Revoke all of a user's credentials, sessions, pending enrollment grants,
     * and unconsumed challenges — the recovery reset.
     *
     * The user must re-enroll through a fresh {@link issueEnrollment} to sign in
     * again. To end sessions while keeping passkeys, use
     * {@link revokeUserSessions} instead.
     */
    revokeUserAuthentication(userId: string): Promise<void>;
    /**
     * Reap expired enrollment grants, finished challenges, and dead sessions.
     * Schedule periodically (every few minutes is ample); credentials are never
     * part of cleanup.
     */
    cleanup(): Promise<CleanupResult>;
}

export { AuthUser, AuthenticationOptionsResult, AuthenticationVerificationInput, AuthenticationVerificationResult, CleanupResult, Credential, EnrollmentExchange, EnrollmentIssue, LocalWebAuthn, LocalWebAuthnError, type LocalWebAuthnErrorCode, LocalWebAuthnOptions, RegistrationOptionsResult, RegistrationVerificationInput, RegistrationVerificationResult, SessionIdentity, createEnrollmentToken, createOpaqueToken, createUserHandle, decodeBase64Url, encodeBase32, encodeBase64Url, equalBytes, isLocalWebAuthnError, sha256 };
