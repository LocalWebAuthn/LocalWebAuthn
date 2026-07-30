import * as _simplewebauthn_server from '@simplewebauthn/server';
import { Base64URLString, AuthenticatorTransportFuture, PublicKeyCredentialRequestOptionsJSON, AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON, RegistrationResponseJSON } from '@simplewebauthn/server';

/**
 * A user record as seen by LocalWebAuthn.
 *
 * The host application owns the user table and maps its columns to this shape.
 * `webAuthnUserHandle` must be a stable, cryptographically random 32-byte value
 * that uniquely identifies the user to WebAuthn authenticators. Use
 * {@link createUserHandle} to generate one at user-creation time.
 *
 * Set `active` to `false` to prevent enrollment, registration, and
 * authentication for a deactivated user.
 */
type AuthUser = {
    /** Application-defined primary key. */
    id: string;
    /** Stable random 32-byte WebAuthn user handle (see {@link createUserHandle}). */
    webAuthnUserHandle: Uint8Array;
    /** Unique human-facing identifier, typically an email address. */
    name: string;
    /** Display name shown in authenticator UI and application chrome. */
    displayName: string;
    /** When `false`, all authentication operations for this user are rejected. */
    active: boolean;
};
/**
 * Host-provided user lookup.
 *
 * The single {@link getUser} method is called on every authentication operation
 * so the host should cache or index by user ID appropriately.
 */
type UserProvider = {
    /** Return the user or `null` if the ID does not exist. */
    getUser(userId: string): Promise<AuthUser | null>;
};
/**
 * A stored passkey credential.
 *
 * `publicKey` is the credential's public key in COSE format. `counter` is the
 * signature counter — each successful authentication increments it, and the
 * store rejects counter values that do not advance, preventing signature replay.
 *
 * `deviceType` and `backedUp` come from the authenticator during registration.
 * `transports` hint at how the authenticator communicates (e.g. `"internal"`,
 * `"hybrid"`).
 */
type Credential = {
    /** WebAuthn credential ID (base64url). */
    id: Base64URLString;
    /** Owning application user ID. */
    userId: string;
    /** COSE-encoded public key. */
    publicKey: Uint8Array;
    /** Signature counter; advances on every authentication. */
    counter: number;
    /** Authenticator transport hints. */
    transports: AuthenticatorTransportFuture[];
    /** `"singleDevice"` or `"multiDevice"` (synced). */
    deviceType: 'singleDevice' | 'multiDevice';
    /** Whether the credential is backed up / synced. */
    backedUp: boolean;
    /** Human-readable label assigned during registration. */
    label: string;
    /** Unix-millisecond timestamp of registration. */
    createdAt: number;
    /** Unix-millisecond timestamp of last authentication, or `null`. */
    lastUsedAt: number | null;
    /** Unix-millisecond timestamp of revocation, or `null` if active. */
    revokedAt: number | null;
};
/**
 * The authenticated identity extracted from a resolved session token.
 *
 * Returned by {@link LocalWebAuthn.resolveSession}; the host uses it to attach
 * user and credential identity to the request context.
 */
type SessionIdentity = {
    userId: string;
    /** The specific credential used in the authentication that created this session. */
    credentialId: string;
    /** When the session was created (authentication time). */
    authenticatedAt: number;
    /** Absolute expiry (session is invalid after this time). */
    expiresAt: number;
    /** Last activity timestamp; updated on each {@link LocalWebAuthn.resolveSession} touch. */
    lastSeenAt: number;
};
type EnrollmentGrantRecord = {
    id: string;
    userId: string;
    tokenHash: Uint8Array;
    expiresAt: number;
    approvedByUserId: string | null;
    createdAt: number;
};
type EnrollmentSession = {
    grantId: string;
    userId: string;
    sessionHash: Uint8Array;
    sessionExpiresAt: number;
};
type ChallengeKind = 'registration' | 'authentication';
type ChallengeRecord = {
    idHash: Uint8Array;
    kind: ChallengeKind;
    challenge: string;
    userId: string | null;
    grantId: string | null;
    authorizationSessionHash: Uint8Array | null;
    expiresAt: number;
    createdAt: number;
};
type ConsumedChallenge = Omit<ChallengeRecord, 'idHash' | 'expiresAt' | 'createdAt'>;
type NewCredential = Omit<Credential, 'lastUsedAt' | 'revokedAt'>;
type NewSession = {
    idHash: Uint8Array;
    userId: string;
    credentialId: string;
    authenticatedAt: number;
    expiresAt: number;
    lastSeenAt: number;
};
type CompleteRegistrationInput = {
    challenge: ConsumedChallenge;
    enrollmentSessionHash: Uint8Array | null;
    authenticatedSessionHash: Uint8Array | null;
    credential: NewCredential;
    session: NewSession;
    now: number;
};
type CompleteAuthenticationInput = {
    credentialId: string;
    previousCounter: number;
    newCounter: number;
    session: NewSession;
    now: number;
};
type CleanupResult = {
    enrollmentGrants: number;
    challenges: number;
    sessions: number;
    orphanedCredentials: number;
};
/**
 * Persistence contract for LocalWebAuthn.
 *
 * Official implementations exist for better-sqlite3
 * ({@link SqliteLocalWebAuthnStore}) and Cloudflare D1
 * ({@link D1LocalWebAuthnStore}). Custom stores must implement every method
 * with the same atomicity and isolation guarantees.
 *
 * **Enrollment flow:** {@link replaceEnrollmentGrant} → {@link exchangeEnrollment}
 * → {@link resolveEnrollmentSession} → (challenge) → {@link completeRegistration}.
 *
 * **Authentication flow:** {@link getCredential} / (challenge) → {@link completeAuthentication}.
 *
 * **Session management:** {@link resolveSession} → {@link touchSession} → {@link revokeSession}.
 *
 * **Maintenance:** {@link cleanup} removes expired grants, challenges, sessions,
 * and orphaned credentials.
 */
type LocalWebAuthnStore = {
    /**
     * Atomically revoke any pending grant for `record.userId` and insert a new one.
     *
     * @returns IDs of grants that were revoked by this operation (for audit events).
     */
    replaceEnrollmentGrant(record: EnrollmentGrantRecord): Promise<string[]>;
    /**
     * Atomically consume an enrollment token, creating an enrollment session.
     *
     * Must be single-use: the first call with a given `tokenHash` succeeds;
     * subsequent calls return `null`. Fails if the token is expired, already
     * consumed, or the grant was revoked.
     */
    exchangeEnrollment(tokenHash: Uint8Array, sessionHash: Uint8Array, sessionExpiresAt: number, now: number): Promise<EnrollmentSession | null>;
    /** Look up an enrollment session by its hashed token. */
    resolveEnrollmentSession(sessionHash: Uint8Array, now: number): Promise<EnrollmentSession | null>;
    /**
     * Insert a challenge record. Returns `true` if inserted, `false` if a
     * challenge with the same `idHash` already exists (extremely unlikely with
     * random 256-bit tokens, but handled defensively).
     */
    createChallenge(record: ChallengeRecord): Promise<boolean>;
    /**
     * Atomically consume a challenge by its hashed token and kind.
     *
     * Must be single-use. Returns the consumed challenge or `null` if it was
     * already consumed, expired, or of the wrong kind.
     */
    consumeChallenge(idHash: Uint8Array, kind: ChallengeKind, now: number): Promise<ConsumedChallenge | null>;
    /**
     * List credentials for a user. By default excludes revoked credentials.
     * Set `includeRevoked` to `true` to see all credentials.
     */
    listCredentials(userId: string, includeRevoked?: boolean): Promise<Credential[]>;
    /** Look up a single credential by its WebAuthn credential ID. */
    getCredential(credentialId: string): Promise<Credential | null>;
    /**
     * Atomically insert a credential, complete its enrollment grant (if any),
     * and create the initial session.
     *
     * Must verify that the enrollment grant or authenticated session is still
     * valid at commit time. Returns `true` on success, `false` if authorization
     * was lost between challenge creation and verification.
     */
    completeRegistration(input: CompleteRegistrationInput): Promise<boolean>;
    /**
     * Atomically advance the credential counter (compare-and-swap) and create a
     * new session.
     *
     * Must reject if the counter has advanced since the challenge was issued.
     * Returns `true` on success, `false` on counter mismatch or credential revocation.
     */
    completeAuthentication(input: CompleteAuthenticationInput): Promise<boolean>;
    /**
     * Resolve a session by its hashed token. Returns `null` if the session is
     * expired, idle, revoked, or the credential is revoked.
     */
    resolveSession(idHash: Uint8Array, now: number, idleExpiresBefore: number): Promise<SessionIdentity | null>;
    /**
     * Update the session's `lastSeenAt` timestamp. Returns `false` if the
     * session was already expired or revoked.
     */
    touchSession(idHash: Uint8Array, now: number): Promise<boolean>;
    /** Mark a session as revoked. Idempotent — returns `false` if already revoked. */
    revokeSession(idHash: Uint8Array, now: number): Promise<boolean>;
    /**
     * Revoke a single credential and all its sessions. Returns `false` if the
     * credential was already revoked or does not belong to `userId`.
     */
    revokeCredential(userId: string, credentialId: string, now: number): Promise<boolean>;
    /**
     * Revoke all credentials and sessions for a user, and invalidate pending
     * enrollment grants and unconsumed challenges.
     */
    revokeUserAuthentication(userId: string, now: number): Promise<void>;
    /**
     * Remove expired enrollment grants, challenges, sessions, and orphaned
     * credentials (those with no session rows, created more than one hour ago).
     *
     * Call periodically (e.g., every few minutes) to reclaim storage.
     */
    cleanup(now: number): Promise<CleanupResult>;
};
type LocalWebAuthnEvent = {
    type: 'enrollment.issued' | 'enrollment.exchanged' | 'enrollment.completed' | 'enrollment.revoked';
    at: number;
    userId: string;
    grantId: string;
} | {
    type: 'credential.registered' | 'credential.authenticated' | 'credential.revoked';
    at: number;
    userId: string;
    credentialId: string;
} | {
    type: 'session.created' | 'session.revoked';
    at: number;
    userId?: string;
    credentialId?: string;
};
type LocalWebAuthnDurations = {
    enrollmentGrantMs?: number;
    enrollmentSessionMs?: number;
    challengeMs?: number;
    sessionIdleMs?: number;
    sessionAbsoluteMs?: number;
};
type CeremonyProvider = {
    generateRegistrationOptions(options: Parameters<typeof _simplewebauthn_server.generateRegistrationOptions>[0]): Promise<PublicKeyCredentialCreationOptionsJSON>;
    verifyRegistrationResponse(options: Parameters<typeof _simplewebauthn_server.verifyRegistrationResponse>[0]): ReturnType<typeof _simplewebauthn_server.verifyRegistrationResponse>;
    generateAuthenticationOptions(options: Parameters<typeof _simplewebauthn_server.generateAuthenticationOptions>[0]): Promise<PublicKeyCredentialRequestOptionsJSON>;
    verifyAuthenticationResponse(options: Parameters<typeof _simplewebauthn_server.verifyAuthenticationResponse>[0]): ReturnType<typeof _simplewebauthn_server.verifyAuthenticationResponse>;
};
/**
 * Configuration for a {@link LocalWebAuthn} instance.
 *
 * ```ts
 * const auth = new LocalWebAuthn({
 *   rpName: 'My Application',
 *   rpId: 'app.example.com',
 *   expectedOrigins: 'https://app.example.com',
 *   store: new SqliteLocalWebAuthnStore(database),
 *   users: { getUser: async (id) => appUsers.get(id) },
 * });
 * ```
 */
type LocalWebAuthnOptions = {
    /** Human-readable relying party name shown in authenticator UI. */
    rpName: string;
    /**
     * Relying party ID — the domain that owns the credential.
     * Must match the registrable domain of every expected origin.
     */
    rpId: string;
    /**
     * Exact HTTPS origin(s) the application serves from.
     * `http://localhost` and `http://127.0.0.1` are allowed for development.
     * Pass a single string or an array for multi-origin deployments.
     */
    expectedOrigins: string | string[];
    /**
     * Publicly visible origin used for constructing enrollment URLs.
     * Defaults to the first expected origin.
     */
    publicOrigin?: string;
    /**
     * URL path for the enrollment page that consumes the `#token=` fragment.
     * Defaults to `"/enroll"`.
     */
    enrollmentPath?: string;
    /** Persistence adapter (see {@link SqliteLocalWebAuthnStore} or {@link D1LocalWebAuthnStore}). */
    store: LocalWebAuthnStore;
    /** Host-provided user lookup. */
    users: UserProvider;
    /** Override default token and session lifetimes (all values in milliseconds). */
    durations?: LocalWebAuthnDurations;
    /**
     * Override the clock. Defaults to `Date.now`. Inject a fixed clock in tests.
     */
    now?: () => number;
    /**
     * Override the random byte source. Defaults to `globalThis.crypto.getRandomValues`.
     */
    randomBytes?: (length: number) => Uint8Array;
    /**
     * Override the WebAuthn ceremony implementation. Defaults to `@simplewebauthn/server`.
     * Inject mock ceremonies in tests.
     */
    ceremonies?: CeremonyProvider;
    /**
     * Observability callback. Receives lifecycle events for audit logging.
     * Errors thrown by this callback are silently caught — authentication has
     * already committed and cannot be rolled back by an observer. The error is
     * forwarded to {@link logger} so operators are not blind to audit-log failures.
     */
    onEvent?: (event: LocalWebAuthnEvent) => void | Promise<void>;
    /**
     * Logger for warnings and errors. Defaults to `console`.
     * Set to `{ warn: () => {}, error: () => {} }` to suppress logging in tests.
     */
    logger?: Pick<typeof console, 'warn' | 'error'>;
};
type EnrollmentIssue = {
    grantId: string;
    enrollmentToken: string;
    enrollmentUrl: string;
    expiresAt: number;
};
type EnrollmentExchange = {
    enrollmentSessionToken: string;
    expiresAt: number;
    user: Pick<AuthUser, 'id' | 'name' | 'displayName'>;
};
type RegistrationOptionsResult = {
    options: PublicKeyCredentialCreationOptionsJSON;
    challengeToken: string;
    expiresAt: number;
};
type RegistrationVerificationResult = {
    verified: true;
    sessionToken: string;
    expiresAt: number;
    credentialId: string;
};
type AuthenticationOptionsResult = {
    options: PublicKeyCredentialRequestOptionsJSON;
    challengeToken: string;
    expiresAt: number;
};
type AuthenticationVerificationResult = {
    verified: true;
    sessionToken: string;
    expiresAt: number;
    credentialId: string;
    user: Pick<AuthUser, 'id' | 'name' | 'displayName'>;
};
type RegistrationVerificationInput = {
    response: RegistrationResponseJSON;
    challengeToken: string;
    enrollmentSessionToken?: string;
    sessionToken?: string;
    label?: string;
};
type AuthenticationVerificationInput = {
    response: AuthenticationResponseJSON;
    challengeToken: string;
};

export type { AuthenticationOptionsResult as A, ChallengeRecord as C, EnrollmentGrantRecord as E, LocalWebAuthnStore as L, NewCredential as N, RegistrationOptionsResult as R, SessionIdentity as S, UserProvider as U, EnrollmentSession as a, ChallengeKind as b, ConsumedChallenge as c, Credential as d, CompleteRegistrationInput as e, CompleteAuthenticationInput as f, CleanupResult as g, LocalWebAuthnOptions as h, EnrollmentIssue as i, EnrollmentExchange as j, RegistrationVerificationInput as k, RegistrationVerificationResult as l, AuthenticationVerificationInput as m, AuthenticationVerificationResult as n, AuthUser as o, CeremonyProvider as p, LocalWebAuthnDurations as q, LocalWebAuthnEvent as r, NewSession as s };
