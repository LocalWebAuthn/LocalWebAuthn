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
    /**
     * Host-defined credential class, fixed at registration and immutable after.
     *
     * Opaque to this package: it takes no position on what a host's categories
     * are. `null` means unclassified, which is every credential registered before
     * the host started setting one.
     *
     * The point of the column is that it is the *only* fact about a credential's
     * class that survives a hostile key holder. `userVerified`, `origin`,
     * `deviceType` and the counter are all asserted by whatever produced the
     * assertion; a software client can claim any of them. This is a server row.
     *
     * See `credentialKinds` in {@link LocalWebAuthnOptions} for the policy that
     * hangs off it.
     */
    kind: string | null;
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
    /**
     * {@link Credential.kind} of the credential that opened this session.
     *
     * Reported here so authorization can depend on it at the moment a session is
     * resolved, without a second lookup. A host that supports machine credentials
     * must consult this on every privileged route — a session opened by a service
     * credential is otherwise indistinguishable from a person's.
     *
     * Note that a freshness check alone is not a human-presence check: a service
     * credential can produce a fresh assertion at will, so a step-up gate must
     * test this field *and* {@link SessionIdentity.authenticatedAt}.
     */
    credentialKind: string | null;
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
    /**
     * Registration challenges only: the {@link Credential.kind} the resulting
     * credential will be given.
     *
     * Written when the options are generated — before the client has seen the
     * challenge — and read back at verification. `verifyRegistration` accepts no
     * kind input of its own, so a client cannot influence its own classification
     * no matter what it puts in the request body.
     */
    credentialKind: string | null;
    /**
     * Authentication challenges only: which {@link Credential.kind} values this
     * ceremony will accept. `null` is unconstrained.
     *
     * This is how a machine-only or browser-only endpoint is enforced centrally
     * rather than in each host route. `null` is a legal member, matching
     * unclassified credentials.
     */
    allowedCredentialKinds: (string | null)[] | null;
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
    /** Expired DPoP proof-replay entries (see {@link LocalWebAuthnStore.claimDpopProof}). */
    dpopProofs: number;
    /** Expired DPoP nonce slots. */
    dpopNonces: number;
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
     * valid at commit time. Returns `true` on success, `false` **only** when
     * authorization was lost between challenge creation and verification.
     *
     * Unexpected storage errors must propagate as thrown exceptions — never be
     * reported as `false`. A swallowed exception here reaches the person
     * enrolling as "your link expired", which is false and undiagnosable.
     */
    completeRegistration(input: CompleteRegistrationInput): Promise<boolean>;
    /**
     * Atomically advance the credential counter (compare-and-swap) and create a
     * new session.
     *
     * Must reject when the stored counter no longer equals `previousCounter`,
     * the credential is revoked, or the new counter is not a valid WebAuthn
     * advance (strict increase, or 0→0). Returns `true` on success; `false` is
     * reserved for that lost compare-and-swap — unexpected storage errors must
     * propagate as thrown exceptions.
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
     * As {@link revokeUserSessions}, scoped to one credential.
     *
     * Used by the kind-filtered form of {@link LocalWebAuthn.revokeUserSessions},
     * which loops over the matching credentials. Same liveness predicates, so the
     * returned counts sum to the same meaning.
     */
    revokeLiveCredentialSessions(credentialId: string, now: number, idleExpiresBefore: number, exceptSessionHash?: Uint8Array): Promise<number>;
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
     * Claim a DPoP proof's `jti` exactly once, for replay detection.
     *
     * Returns `true` when this digest was newly recorded and `false` when it was
     * already present — which is a replayed proof and must fail the request.
     * `expiresAt` is when the entry may be reaped, normally the end of the
     * acceptance window the proof's `iat` implies; it is absolute, so no clock is
     * passed.
     *
     * Must be atomic: two concurrent requests carrying the same `jti` must not
     * both see `true`.
     */
    claimDpopProof(jtiHash: Uint8Array, expiresAt: number): Promise<boolean>;
    /**
     * Return the deployment-wide DPoP nonce for `slot`, inserting `candidate` if no
     * server has claimed that slot yet.
     *
     * `slot` is `floor(now / rotationMs)`, so every server computes the same one and
     * whichever inserts first decides the value — the primary key is the only
     * coordination needed. Must return the *stored* nonce, not `candidate`, or two
     * servers would disagree.
     */
    claimDpopNonce(slot: number, candidate: string, expiresAt: number): Promise<string>;
    /**
     * Nonces for the current and previous slot, in any order, omitting slots that
     * have never been claimed.
     *
     * Two are accepted so a rotation landing mid-flight does not reject a proof the
     * client built moments earlier against the outgoing value.
     */
    dpopNonces(currentSlot: number, previousSlot: number): Promise<string[]>;
    /**
     * Remove expired enrollment grants, finished challenges, dead sessions, and
     * spent DPoP proof records.
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
    /** {@link Credential.kind}, so an audit trail can tell a person from a program. */
    credentialKind?: string | null;
} | {
    type: 'session.created' | 'session.revoked';
    at: number;
    userId?: string;
    credentialId?: string;
    credentialKind?: string | null;
} | {
    /** Bulk session revoke ("sign out everywhere"): credentials and grants untouched. */
    type: 'user.sessions_revoked';
    at: number;
    userId: string;
    /** Live sessions revoked; an excepted session is not counted. */
    count: number;
    /** Credential kinds the revoke was scoped to, when it was scoped. */
    kinds?: (string | null)[];
} | {
    /**
     * Bulk recovery revoke: credentials, sessions, and — only when unscoped —
     * grants and challenges.
     */
    type: 'user.authentication_revoked';
    at: number;
    userId: string;
    /** Credential kinds the revoke was scoped to, when it was scoped. */
    kinds?: (string | null)[];
};
type LocalWebAuthnDurations = {
    enrollmentGrantMs?: number;
    enrollmentSessionMs?: number;
    challengeMs?: number;
    sessionIdleMs?: number;
    sessionAbsoluteMs?: number;
};
/**
 * Policy for one host-defined {@link Credential.kind}.
 *
 * Declaring a kind here is what turns it from a label into a restriction. Kinds
 * that are *not* declared — including `null`, which every pre-existing
 * credential has — behave exactly as they did before this option existed, so
 * adding the option changes nothing until a host opts in.
 *
 * That asymmetry is deliberate. The alternative default, "unknown kinds are
 * non-interactive", would lock out any host that backfilled `kind: 'person'`
 * onto its human credentials.
 */
type CredentialKindPolicy = {
    /**
     * Whether {@link LocalWebAuthn.authenticationOptions} admits this kind when
     * the caller does not name it explicitly. Defaults to `true`.
     *
     * Set `false` for machine credentials: the browser sign-in route then cannot
     * accept one even by mistake, and the machine route must ask for it by name.
     */
    interactive?: boolean;
    /**
     * Whether a session opened by this kind may authorize registering a new
     * credential. Defaults to `true`.
     *
     * Set `false` for machine credentials. Otherwise a leaked key can register a
     * second credential and outlive revocation of the first, which makes
     * revocation useless as a remedy — the credential replicates itself. The cost
     * is that unattended key rotation has to go back through a human-authorized
     * enrollment instead of chaining off the old key.
     */
    canRegister?: boolean;
    /** Absolute session lifetime for this kind, overriding `durations.sessionAbsoluteMs`. */
    sessionAbsoluteMs?: number;
    /** Idle session lifetime for this kind, overriding `durations.sessionIdleMs`. */
    sessionIdleMs?: number;
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
     * Enable DPoP nonce issuance (RFC 9449 section 8).
     *
     * Presence enables it; absence means {@link LocalWebAuthn.dpopNonce} returns
     * `null` and asking `verifyDpop` to require one is a configuration error. Left
     * off by default because it costs the client something real: it must retain the
     * most recent `DPoP-Nonce` and retry once when the server demands one.
     * `@localwebauthn/client` already does both, but a hand-written client would
     * have to.
     *
     * Worth enabling once credential keys live in hardware, which is when
     * "possession of the key" and "able to sign right now" stop being the same
     * thing — a nonce is what makes that distinction enforceable server-side.
     */
    dpopNonce?: {
        /**
         * How often the nonce changes, in milliseconds. Defaults to 5 minutes.
         *
         * A proof is accepted against the current or previous slot, so this is also
         * roughly how long a pre-generated proof could remain usable.
         */
        rotationMs?: number;
    };
    /**
     * Per-kind policy, keyed by {@link Credential.kind}.
     *
     * ```ts
     * credentialKinds: {
     *   service: { interactive: false, canRegister: false, sessionAbsoluteMs: 15 * 60_000 },
     * }
     * ```
     */
    credentialKinds?: Record<string, CredentialKindPolicy>;
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
    /** {@link Credential.kind} the new credential was given. */
    credentialKind: string | null;
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
    /**
     * {@link Credential.kind} of the credential that authenticated, so the host
     * can decide what this session may do without a second lookup.
     */
    credentialKind: string | null;
    user: Pick<AuthUser, 'id' | 'name' | 'displayName'>;
};
type RegistrationOptionsInput = {
    enrollmentSessionToken?: string;
    sessionToken?: string;
    /**
     * {@link Credential.kind} to give the credential this ceremony creates.
     *
     * Supplied by the *host route*, from what it decided to authorize — never
     * forwarded from the request body, or the client would be classifying itself.
     * Recorded on the challenge, so the class is settled on a server row before
     * the client is handed a challenge, and {@link RegistrationVerificationInput}
     * has no corresponding field at all.
     */
    credentialKind?: string;
};
type AuthenticationOptionsInput = {
    /**
     * Restrict this ceremony to these {@link Credential.kind} values. `null` is a
     * legal member and matches unclassified credentials.
     *
     * Omit to admit every kind not declared `interactive: false` in
     * `credentialKinds` — so a browser route needs no argument, and a machine
     * route names its kind explicitly.
     */
    credentialKinds?: (string | null)[];
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

export type { AuthenticationOptionsInput as A, ChallengeRecord as C, EnrollmentGrantRecord as E, LocalWebAuthnStore as L, NewCredential as N, RevokedSession as R, SessionIdentity as S, UserProvider as U, EnrollmentSession as a, ChallengeKind as b, ConsumedChallenge as c, Credential as d, CompleteRegistrationInput as e, CompleteAuthenticationInput as f, RevokeCredentialResult as g, CleanupResult as h, LocalWebAuthnOptions as i, EnrollmentIssue as j, EnrollmentExchange as k, RegistrationOptionsInput as l, RegistrationOptionsResult as m, RegistrationVerificationInput as n, RegistrationVerificationResult as o, AuthenticationOptionsResult as p, AuthenticationVerificationInput as q, AuthenticationVerificationResult as r, AuthUser as s, CeremonyProvider as t, LocalWebAuthnDurations as u, LocalWebAuthnEvent as v, NewSession as w };
