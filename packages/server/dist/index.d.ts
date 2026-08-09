import { j as LocalWebAuthnOptions, k as EnrollmentIssue, l as EnrollmentExchange, m as RegistrationOptionsInput, n as RegistrationOptionsResult, o as RegistrationVerificationInput, p as RegistrationVerificationResult, A as AuthenticationOptionsInput, q as AuthenticationOptionsResult, r as AuthenticationVerificationInput, s as AuthenticationVerificationResult, t as AuthUser, S as SessionIdentity, e as Credential, i as CleanupResult } from './types-BkXhC9Te.js';
export { u as CeremonyProvider, c as ChallengeKind, C as ChallengeRecord, g as CompleteAuthenticationInput, f as CompleteRegistrationInput, d as ConsumedChallenge, v as CredentialKindPolicy, w as CredentialProvenance, E as EnrollmentGrantRecord, b as EnrollmentSession, a as LocalWebAuthnDpopStore, x as LocalWebAuthnDurations, y as LocalWebAuthnEvent, L as LocalWebAuthnStore, N as NewCredential, z as NewSession, h as RevokeCredentialResult, R as RevokedSession, U as UserProvider } from './types-BkXhC9Te.js';
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

type NormalizedCredentialKind = {
    interactive: boolean;
    canRegister: boolean;
    sessionAbsoluteMs: number;
};
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
    /** Declared kinds only; an undeclared kind falls back to {@link defaultKindPolicy}. */
    credentialKinds: Record<string, NormalizedCredentialKind>;
    /** `null` when nonce issuance was not configured. */
    dpopNonce: {
        rotationMs: number;
    } | null;
};
/**
 * Policy for a kind the host never declared, including `null`.
 *
 * Permissive on purpose: an undeclared kind must behave exactly as it did before
 * `credentialKinds` existed, or adding the option would silently change
 * behaviour for every deployment that ignores it.
 */
declare function defaultKindPolicy(config: NormalizedConfig): NormalizedCredentialKind;
/** Effective policy for `kind`, falling back to {@link defaultKindPolicy}. */
declare function kindPolicy(config: NormalizedConfig, kind: string | null): NormalizedCredentialKind;

/**
 * DPoP (RFC 9449) proof verification, bound to a stored WebAuthn credential.
 *
 * The usual OAuth deployment stores a `jkt` — the thumbprint of the key that
 * will sign proofs — alongside each access token, because there the DPoP key is
 * unrelated to whatever authenticated the client. Here it *is* the credential
 * key: a software client signs its WebAuthn assertion and its DPoP proofs with
 * one key, so the expected thumbprint is derived from `credentials.public_key`
 * and there is nothing new to store per session.
 *
 * The per-request check therefore reduces to: this proof was signed by the same
 * key that produced the assertion that opened this session.
 *
 * Reusing one key across the two protocols is safe because the signed inputs
 * cannot collide. A WebAuthn assertion covers `authenticatorData ‖
 * SHA-256(clientDataJSON)` — 69 bytes opening with a SHA-256 digest — while a
 * JWS signing input is printable ASCII that always begins `eyJ`. The separation
 * is structural, not a coincidence of encoding.
 */
/** Public JWK for an EC2 P-256 or OKP Ed25519 key. */
type PublicJwk = {
    kty: 'EC';
    crv: 'P-256';
    x: string;
    y: string;
} | {
    kty: 'OKP';
    crv: 'Ed25519';
    x: string;
};
type DpopVerificationInput = {
    /** Raw `DPoP` header value: a compact JWS. */
    proof: string;
    /** Request method, e.g. `"POST"`. */
    method: string;
    /** Full request URL; query and fragment are stripped before comparison. */
    url: string;
    /** The session token this proof accompanies, hashed into the `ath` claim. */
    accessToken: string;
    /** COSE public key of the credential that opened the session. */
    publicKeyCose: Uint8Array;
    /**
     * When non-empty, the proof's `nonce` must be one of these — normally the
     * current and previous rotation slot, so a rotation landing mid-flight does not
     * reject a proof built moments earlier.
     */
    nonces?: string[];
    /** Accepted clock skew for `iat`, in milliseconds. Defaults to 60s either way. */
    skewMs?: number;
    now?: number;
};
type DpopVerification = {
    valid: true;
    /** SHA-256 of the `jti`, for the single-use claim in the store. */
    jtiHash: Uint8Array;
    /** When the replay-cache entry may be reaped. */
    expiresAt: number;
} | {
    valid: false;
    reason: string;
};
/**
 * Convert a COSE public key to its public JWK form.
 *
 * Returns `null` for key types this package does not register (RSA), or for a
 * structurally incomplete key.
 */
declare function coseToJwk(publicKeyCose: Uint8Array): PublicJwk | null;
/**
 * RFC 7638 JWK thumbprint.
 *
 * The canonical form contains only the required members, in lexicographic order,
 * with no whitespace — so the JSON below is written by hand rather than by
 * `JSON.stringify` over an object whose key order would be incidental.
 */
declare function jwkThumbprint(jwk: PublicJwk): Promise<string>;
/**
 * Verify a DPoP proof against the credential that opened the session.
 *
 * Checks, in order: the compact JWS shape; `typ` and `alg`; that the embedded
 * `jwk` is the credential's own key, by thumbprint; the signature; then `htm`,
 * `htu`, `iat`, `ath` and `nonce`.
 *
 * A `true` result still requires the caller to claim `jtiHash` through
 * {@link LocalWebAuthnStore.claimDpopProof} — this function is pure and cannot
 * detect replay by itself.
 */
declare function verifyDpopProof(input: DpopVerificationInput): Promise<DpopVerification>;

type LocalWebAuthnErrorCode = 'invalid_configuration' | 'invalid_enrollment' | 'enrollment_not_authorized' | 'invalid_ceremony' | 'registration_failed' | 'authentication_failed' | 'unauthenticated' | 'credential_not_found' | 'last_credential'
/**
 * The authorizing session's credential kind is configured `canRegister: false`
 * — a machine credential may authenticate but may not enroll another
 * credential. See {@link CredentialKindPolicy.canRegister}.
 */
 | 'registration_not_permitted'
/** A DPoP proof was absent, malformed, replayed, or signed by the wrong key. */
 | 'invalid_dpop_proof'
/**
 * A DPoP proof carried no nonce, or one the server no longer recognises. The
 * host should answer `401` with `WWW-Authenticate: DPoP
 * error="use_dpop_nonce"` and a fresh `DPoP-Nonce` header, which the client
 * echoes on its retry.
 */
 | 'dpop_nonce_required';
declare class LocalWebAuthnError extends Error {
    readonly code: LocalWebAuthnErrorCode;
    readonly status: number;
    constructor(code: LocalWebAuthnErrorCode, message: string, status: number);
}
declare function isLocalWebAuthnError(value: unknown): value is LocalWebAuthnError;

/**
 * Framework-neutral HTTP helpers for host adapters.
 *
 * LocalWebAuthn does not set cookies or read `Origin` itself. These helpers
 * encode the cookie attributes and exact-origin checks described in SECURITY.md
 * so every starter (and the demo) shares one correct implementation.
 */
type AuthCookieKind = 'challenge' | 'enrollment' | 'session';
type AuthCookieNames = Record<AuthCookieKind, string>;
/**
 * Attributes for an opaque auth cookie (challenge, enrollment, or session).
 *
 * Compatible with `hono/cookie` `setCookie` options and with manual
 * `Set-Cookie` construction. `__Host-` names are chosen by
 * {@link authCookieNames} when the public origin is HTTPS; those names require
 * `secure: true`, `path: '/'`, and no `Domain` attribute.
 */
type CookieAttributes = {
    httpOnly: true;
    path: '/';
    sameSite: 'Strict';
    secure: boolean;
    /** Seconds until expiry; omit when clearing a cookie. */
    maxAge?: number;
};
type CookieAttributesOptions = {
    /** Exact public origin of the app (`https://app.example.com` or local HTTP). */
    publicOrigin: string;
    /** Absolute expiry as a Unix millisecond timestamp (from LocalWebAuthn APIs). */
    expiresAt?: number;
    /** Override the clock (tests). */
    now?: () => number;
};
/**
 * Whether `publicOrigin` is HTTPS (so cookies may use the `__Host-` prefix).
 */
declare function isHttpsPublicOrigin(publicOrigin: string): boolean;
/**
 * Cookie names for the three opaque tokens.
 *
 * On HTTPS origins, names use the `__Host-` prefix (Secure, Path=/, no Domain).
 * On loopback HTTP (`http://localhost`, `http://127.0.0.1`), plain names are
 * used because browsers reject `__Host-` without `Secure`. Any other `http://`
 * origin throws — see {@link cookieAttributes}.
 *
 * @param namespace - Short prefix, default `lwa`. Demo uses `lwa_demo`.
 */
declare function authCookieNames(publicOrigin: string, namespace?: string): AuthCookieNames;
/**
 * Cookie attributes for setting or clearing an opaque auth token.
 *
 * When `expiresAt` is provided, `maxAge` is derived in whole seconds (minimum 1).
 * When omitted, no `maxAge` is set (suitable for delete/clear).
 *
 * Throws for a plain-HTTP `publicOrigin` that is not loopback: WebAuthn will
 * not run there, and issuing non-`Secure` cookies for it would only hide the
 * misconfiguration.
 */
declare function cookieAttributes(options: CookieAttributesOptions): CookieAttributes;
/**
 * Response headers that ask a DPoP client to retry with a server-issued nonce
 * (RFC 9449 section 8).
 *
 * Send these with a `401` when `verifyDpop` throws `dpop_nonce_required`, passing
 * the value of `auth.dpopNonce()`. Without a helper this is four things to get
 * right in every host — catch the code, fetch a nonce, name both headers exactly
 * — for one fixed protocol behaviour.
 *
 * The nonce is not a secret: the server hands the current one to any caller, and
 * its only property is being unguessable *in advance*. So answering a request
 * that failed authentication with one gives nothing away. `null` or `undefined`
 * (nonces not configured) yields the challenge without the nonce header, which is
 * a client-side bug worth surfacing rather than hiding.
 */
declare function dpopChallenge(nonce?: string | null): Record<string, string>;
/**
 * Exact-origin check for state-changing requests.
 *
 * Pass the `Origin` header value (or `null` if absent). Returns true only when
 * it exactly equals `expectedOrigin` (scheme + host + port, no path).
 */
declare function isExactOrigin(requestOrigin: string | null | undefined, expectedOrigin: string): boolean;
/**
 * Parse a `Cookie` header into a name → value map (first value wins).
 *
 * Values are returned raw, with no percent-decoding — LocalWebAuthn tokens are
 * URL-safe base32 and never need it. Do not use this as a general-purpose
 * cookie parser for values a framework may have percent-encoded.
 */
declare function parseCookieHeader(header: string | null | undefined): Record<string, string>;
/**
 * Build a single `Set-Cookie` header value (for plain Node or undici adapters).
 *
 * Throws `TypeError` when `name` or `value` contains characters RFC 6265 does
 * not allow (which would otherwise corrupt or inject headers). LocalWebAuthn
 * tokens are URL-safe base32 and always pass.
 */
declare function serializeCookie(name: string, value: string, attributes: CookieAttributes): string;
/**
 * `Set-Cookie` value that clears a cookie (empty value, maxAge 0).
 */
declare function serializeClearedCookie(name: string, publicOrigin: string): string;

/**
 * Host-owned passkey signup / enrollment sequencing.
 *
 * LocalWebAuthn stores grants, credentials, and sessions — not application
 * users. This module does not write to the database. It names the phases a
 * host app moves through so signup UIs and APIs share one vocabulary and do
 * not invent ad-hoc “pending” flags that drift from the store.
 *
 * Typical happy path:
 *
 * 1. Host creates a user row with {@link createUserHandle} (phase `created`).
 * 2. Host proves channels / admin approval as product policy.
 * 3. Host calls `issueEnrollment` (phase `enrollment_issued`).
 * 4. Browser opens the fragment, `exchangeEnrollment` (phase `enrollment_exchanged`).
 * 5. `verifyRegistration` creates a credential (phase `enrolled`).
 *
 * Recovery returns to `enrollment_issued` after `revokeUserAuthentication`
 * plus a new `issueEnrollment` (see demo **Re-enroll**).
 */
type SignupPhase = 'created' | 'enrollment_issued' | 'enrollment_exchanged' | 'enrolled';
/**
 * Observable facts the host can load without guessing.
 *
 * - `hasActiveCredential` — `listCredentials(userId).length > 0`
 * - `hasPendingEnrollmentGrant` — host tracks issued grants, or treats a
 *   non-null enrollment session / product “pending invite” flag as true
 * - `hasEnrollmentSession` — browser has a valid enrollment cookie (host may
 *   only know this on register routes)
 */
type SignupFacts = {
    hasActiveCredential: boolean;
    hasPendingEnrollmentGrant: boolean;
    hasEnrollmentSession: boolean;
};
/**
 * Derive the current signup phase from store/session facts.
 *
 * Credentials win: once a passkey exists, the user is `enrolled` even if an
 * old grant row still exists until cleanup.
 */
declare function signupPhase(facts: SignupFacts): SignupPhase;
type SignupNextStep = {
    action: 'issue_enrollment';
    reason: string;
} | {
    action: 'deliver_enrollment_url';
    reason: string;
} | {
    action: 'register_passkey';
    reason: string;
} | {
    action: 'done';
    reason: string;
};
/**
 * Human-oriented next step for admin UIs and automated signup workers.
 */
declare function nextSignupStep(phase: SignupPhase): SignupNextStep;
/**
 * Short description for logs and admin tables.
 */
declare function describeSignupPhase(phase: SignupPhase): string;
/**
 * Recommended host steps for automated self-serve signup (no standing email login).
 *
 * Implementations prove channels first, then call LocalWebAuthn — this list is
 * the contract, not executable I/O.
 */
declare const SELF_SERVE_SIGNUP_STEPS: readonly ["Collect identifiers (e.g. email and phone) and rate-limit the form", "Verify control of two independent channels before creating durable access", "Insert application user with createUserHandle(); do not store a password", "Call issueEnrollment(userId); store only the URL for delivery, never log the raw token long-term", "Deliver the enrollment URL on a bound channel (not an attacker-supplied address)", "User opens fragment → exchangeEnrollment → registerPasskey", "Optionally prompt for a second passkey while the session is fresh"];

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
     * @param options.approvedByUserId - ID of the administrator who approved this
     *   enrollment, recorded on the grant and on any credential it creates.
     * @param options.credentialKind - The {@link Credential.kind} this grant may
     *   create. Confines the token to that class: whichever route redeems it, the
     *   resulting credential gets this kind and its restrictions.
     * @returns The enrollment URL (with `#token=` fragment), raw token, expiry,
     *   and the IDs of any grants this issue superseded.
     */
    issueEnrollment(userId: string, options?: {
        approvedByUserId?: string;
        credentialKind?: string;
    }): Promise<EnrollmentIssue>;
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
    registrationOptions(input: RegistrationOptionsInput): Promise<RegistrationOptionsResult>;
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
    verifyRegistration(input: RegistrationVerificationInput): Promise<RegistrationVerificationResult>;
    /**
     * Create discoverable-credential authentication options with
     * `userVerification: 'required'` and a single-use challenge token.
     *
     * No user is identified at this point; the authenticator chooses the
     * credential and {@link verifyAuthentication} resolves and checks the user.
     */
    authenticationOptions(input?: AuthenticationOptionsInput): Promise<AuthenticationOptionsResult>;
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
    revokeUserSessions(userId: string, options?: {
        exceptSessionToken?: string;
        kinds?: (string | null)[];
    }): Promise<number>;
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
    interactiveKind(kind: string | null): boolean;
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
    credentialLineage(userId: string, credentialId: string): Promise<Credential[]>;
    /**
     * A credential and everything descended from it, nearest first.
     *
     * Index 0 is the credential itself. This is the blast radius of a compromised
     * credential: everything it was used to enroll, and everything those enrolled.
     */
    credentialDescendants(userId: string, credentialId: string): Promise<Credential[]>;
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
     * @returns IDs actually revoked, root first. Already-revoked ones are skipped.
     */
    revokeCredentialTree(userId: string, credentialId: string, options?: {
        kinds?: (string | null)[];
    }): Promise<string[]>;
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
    revokeUserAuthentication(userId: string, options?: {
        kinds?: (string | null)[];
    }): Promise<void>;
    /**
     * Reap expired enrollment grants, finished challenges, and dead sessions.
     * Schedule periodically (every few minutes is ample); credentials are never
     * part of cleanup.
     */
    cleanup(): Promise<CleanupResult>;
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
    dpopNonce(): Promise<string | null>;
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
    verifyDpop(input: {
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
    }): Promise<void>;
}

export { type AuthCookieKind, type AuthCookieNames, AuthUser, AuthenticationOptionsInput, AuthenticationOptionsResult, AuthenticationVerificationInput, AuthenticationVerificationResult, CleanupResult, type CookieAttributes, type CookieAttributesOptions, Credential, type DpopVerification, type DpopVerificationInput, EnrollmentExchange, EnrollmentIssue, LocalWebAuthn, LocalWebAuthnError, type LocalWebAuthnErrorCode, LocalWebAuthnOptions, type NormalizedConfig, type NormalizedCredentialKind, type PublicJwk, RegistrationOptionsInput, RegistrationOptionsResult, RegistrationVerificationInput, RegistrationVerificationResult, SELF_SERVE_SIGNUP_STEPS, SessionIdentity, type SignupFacts, type SignupNextStep, type SignupPhase, authCookieNames, cookieAttributes, coseToJwk, createEnrollmentToken, createOpaqueToken, createUserHandle, decodeBase64Url, defaultKindPolicy, describeSignupPhase, dpopChallenge, encodeBase32, encodeBase64Url, equalBytes, isExactOrigin, isHttpsPublicOrigin, isLocalWebAuthnError, jwkThumbprint, kindPolicy, nextSignupStep, parseCookieHeader, serializeClearedCookie, serializeCookie, sha256, signupPhase, verifyDpopProof };
