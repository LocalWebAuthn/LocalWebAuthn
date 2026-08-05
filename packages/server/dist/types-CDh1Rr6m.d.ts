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
 * signature counter. Successful authentication compare-and-swaps it forward;
 * the store rejects a non-increasing value when either the stored or reported
 * counter is non-zero (WebAuthn clone detection). A 0→0 update is allowed for
 * authenticators that do not implement counters.
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
/**
 * Rows removed by {@link LocalWebAuthnStore.cleanup}.
 *
 * Cleanup reaps ephemeral rows only (expired grants, finished challenges, dead
 * sessions). Credentials are not part of cleanup — they are durable
 * authenticators managed only by registration and revocation.
 */
type CleanupResult = {
    enrollmentGrants: number;
    challenges: number;
    sessions: number;
};
/** Outcome of {@link LocalWebAuthnStore.revokeCredential}. */
type RevokeCredentialResult = 'revoked' | 'not_found' | 'last_credential';
/** Identity returned when a session is newly revoked. */
type RevokedSession = {
    userId: string;
    credentialId: string;
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
 * **Session management:** {@link resolveSession} → {@link touchSession} →
 * {@link revokeSession} / {@link revokeUserSessions}.
 *
 * **Maintenance:** {@link cleanup} removes expired grants, challenges, and
 * sessions.
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
     * Must reject when the stored counter no longer equals `previousCounter`,
     * the credential is revoked, or the new counter is not a valid WebAuthn
     * advance (strict increase, or 0→0). Returns `true` on success.
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
    /**
     * Mark a session as revoked. Returns the session identity when a row was
     * newly revoked, or `null` if the token was unknown or already revoked.
     */
    revokeSession(idHash: Uint8Array, now: number): Promise<RevokedSession | null>;
    /**
     * Revoke every live session for a user, leaving credentials and enrollment
     * grants untouched.
     *
     * A session is live when it is not revoked, not past its absolute expiry at
     * `now`, and its `lastSeenAt` is after `idleExpiresBefore` — the same
     * predicates {@link resolveSession} applies. When `exceptSessionHash` is
     * given, the matching session is spared ("sign out everywhere else").
     *
     * @returns The number of live sessions revoked.
     */
    revokeUserSessions(userId: string, now: number, idleExpiresBefore: number, exceptSessionHash?: Uint8Array): Promise<number>;
    /**
     * Revoke a single credential and all its sessions.
     *
     * When `allowLastCredential` is false (the default), the store must refuse
     * to revoke the user's only remaining active credential and return
     * `"last_credential"`. That check must be atomic with the revoke on engines
     * that support transactions (SQLite, PostgreSQL); D1 uses a single
     * conditional `UPDATE` for the same predicate.
     */
    revokeCredential(userId: string, credentialId: string, now: number, options?: {
        allowLastCredential?: boolean;
    }): Promise<RevokeCredentialResult>;
    /**
     * Revoke all credentials and sessions for a user, and invalidate pending
     * enrollment grants and unconsumed challenges.
     */
    revokeUserAuthentication(userId: string, now: number): Promise<void>;
    /**
     * Remove expired enrollment grants, finished challenges, and dead sessions.
     *
     * Call periodically (e.g. every few minutes) to reclaim storage. Does not
     * touch credentials.
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
} | {
    /** Bulk session revoke ("sign out everywhere"): credentials and grants untouched. */
    type: 'user.sessions_revoked';
    at: number;
    userId: string;
    /** Live sessions revoked; an excepted session is not counted. */
    count: number;
} | {
    /** Bulk recovery revoke: credentials, sessions, grants, and challenges. */
    type: 'user.authentication_revoked';
    at: number;
    userId: string;
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
    /**
     * Pending grants revoked because this issue superseded them (usually zero or
     * one). Returned so the host can record the replacement durably in its own
     * transaction; the matching `enrollment.revoked` events remain best-effort.
     */
    supersededGrantIds: string[];
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

export type { AuthenticationOptionsResult as A, ChallengeRecord as C, EnrollmentGrantRecord as E, LocalWebAuthnStore as L, NewCredential as N, RevokedSession as R, SessionIdentity as S, UserProvider as U, EnrollmentSession as a, ChallengeKind as b, ConsumedChallenge as c, Credential as d, CompleteRegistrationInput as e, CompleteAuthenticationInput as f, RevokeCredentialResult as g, CleanupResult as h, LocalWebAuthnOptions as i, EnrollmentIssue as j, EnrollmentExchange as k, RegistrationOptionsResult as l, RegistrationVerificationInput as m, RegistrationVerificationResult as n, AuthenticationVerificationInput as o, AuthenticationVerificationResult as p, AuthUser as q, CeremonyProvider as r, LocalWebAuthnDurations as s, LocalWebAuthnEvent as t, NewSession as u };
