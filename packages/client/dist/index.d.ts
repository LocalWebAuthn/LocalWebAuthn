/**
 * Key custody.
 *
 * Nothing in this package assumes the private key is in memory. Everything a
 * credential needs from its key is behind {@link MachineKeyStore}, so a TPM, a
 * Secure Enclave, a PKCS#11 token or a cloud KMS can be dropped in behind the
 * same four members.
 *
 * Only the WebCrypto backend ships here, because it is the only one portable to
 * both a browser and a server runtime. The rest need platform bindings and
 * belong in host code — see `docs/API-AUTH.org`, /Key Custody/, for the
 * `keystore:` URI scheme and each backend's limits.
 *
 * Two of those limits are worth knowing before choosing: every non-exportable
 * backend is ES256-only, and Secure Enclave and TPM keys cannot be *imported* at
 * all — they are generated in place, so a key minted in a browser page can never
 * reach them.
 */
/** COSE algorithm identifiers this package supports. */
type CoseAlgorithm = -7 | -8;
/** ECDSA P-256 with SHA-256. The only algorithm hardware backends offer. */
declare const ES256: -7;
/** Ed25519. Avoids the DER/raw signature split, but software-only in practice. */
declare const EDDSA: -8;
type MachineKeyStore = {
    readonly algorithm: CoseAlgorithm;
    /** COSE_Key encoding of the public half, for registration. */
    publicKeyCose(): Promise<Uint8Array>;
    /** Public JWK, for the `jwk` header of a DPoP proof. */
    publicJwk(): Promise<JsonWebKey>;
    /** WebAuthn-shaped signature: DER for ES256, raw for EdDSA. */
    signWebAuthn(data: Uint8Array): Promise<Uint8Array>;
    /** JWS-shaped signature: raw `r ‖ s` for ES256, raw for EdDSA. */
    signJws(data: Uint8Array): Promise<Uint8Array>;
};
/**
 * Generate a fresh key pair.
 *
 * `exportPrivateKey` is what the provisioning page calls to render the one-time
 * `.env` line; it throws when the key was generated non-extractable.
 */
declare function generateKeyStore(algorithm?: CoseAlgorithm, extractable?: boolean): Promise<{
    keyStore: MachineKeyStore;
    exportPrivateKey: () => Promise<string>;
}>;
/**
 * Open a key store over a base64 PKCS#8 private key.
 *
 * The key is imported twice: once extractable, only to read the public members
 * out of its JWK — WebCrypto offers no way to derive a public key from a private
 * `CryptoKey` — and once non-extractable, which is the handle that actually
 * signs. So a process that read the key from a file cannot later be induced to
 * hand it back out through the signing handle.
 */
declare function importKeyStore(privateKeyBase64: string, algorithm?: CoseAlgorithm): Promise<MachineKeyStore>;

/**
 * A WebAuthn authenticator implemented in software.
 *
 * "Authenticator" in WebAuthn is a *role*, not a device class. Its obligations
 * are to hold a key pair, emit `authenticatorData`, and sign — all three of which
 * are discharged below in a few dozen lines. The W3C specification standardises a
 * Virtual Authenticator precisely so software can occupy the role, and every
 * WebAuthn test suite in existence drives one.
 *
 * What such an authenticator cannot honestly claim is human presence. It sets the
 * UP and UV bits because a conforming relying party checks them, but those bits
 * are a program's statement about itself, and a server must never read them as
 * evidence of a person. That is what the credential's server-side `kind` is for.
 */

type SoftwareCredential = {
    /** Raw credential ID; the server stores its base64url form as the primary key. */
    credentialId: Uint8Array;
    /** 32-byte WebAuthn user handle, from `options.user.id`. */
    userHandle: Uint8Array;
    rpId: string;
    /** Exact string written into `clientDataJSON.origin`. */
    origin: string;
};
/** Minimal shape of the registration response this authenticator emits. */
type SoftwareRegistrationResponse = {
    id: string;
    rawId: string;
    type: 'public-key';
    clientExtensionResults: Record<string, never>;
    response: {
        clientDataJSON: string;
        attestationObject: string;
        transports: string[];
    };
};
/** Minimal shape of the assertion this authenticator emits. */
type SoftwareAssertionResponse = {
    id: string;
    rawId: string;
    type: 'public-key';
    clientExtensionResults: Record<string, never>;
    response: {
        clientDataJSON: string;
        authenticatorData: string;
        signature: string;
        userHandle: string;
    };
};
/**
 * Produce a registration response for a freshly generated key.
 *
 * `BE` and `BS` are deliberately clear, so the server records
 * `deviceType: 'singleDevice'` and `backedUp: false` — honest for a key that
 * lives in a file, and notably *not* the "synced passkey" a `multiDevice` row
 * would imply.
 *
 * With `fmt: "none"` there is no attestation signature at all: the public key is
 * simply asserted, and the first assertion is what proves the private half
 * exists.
 */
declare function createRegistrationResponse(input: {
    keyStore: MachineKeyStore;
    challenge: string;
    rpId: string;
    origin: string;
    credentialId?: Uint8Array;
}): Promise<{
    response: SoftwareRegistrationResponse;
    credentialId: Uint8Array;
}>;
/** Produce an assertion for a server-issued challenge. */
declare function createAssertionResponse(input: {
    keyStore: MachineKeyStore;
    credential: SoftwareCredential;
    challenge: string;
}): Promise<SoftwareAssertionResponse>;

/**
 * Byte and base64 helpers.
 *
 * Deliberately duplicated rather than imported from `@localwebauthn/server`: a
 * client that talks to a LocalWebAuthn server must not have to install the
 * server, and this file has no dependencies at all.
 */
declare function utf8(value: string): Uint8Array;
declare function concat(...parts: Uint8Array[]): Uint8Array;
declare function encodeBase64(bytes: Uint8Array): string;
declare function decodeBase64(value: string): Uint8Array;
declare function encodeBase64Url(bytes: Uint8Array): string;
declare function decodeBase64Url(value: string): Uint8Array;
declare function sha256(value: Uint8Array | string): Promise<Uint8Array>;
declare function randomBytes(length: number): Uint8Array;

/**
 * The two-line `.env` credential format.
 *
 * ```conf
 * # nightly-export -- created 2026-08-08
 * LWA_CREDENTIAL='{"v":1,"baseUrl":"https://app.example.com",...}'
 * LWA_CREDENTIAL_KEY=MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...
 * ```
 *
 * One secret, several public values. Everything in `LWA_CREDENTIAL` is safe in a
 * log or a support ticket; only the key line matters.
 *
 * **The single quotes are load-bearing.** Without them `source .env` lets the
 * shell strip the JSON's double quotes. With them, no field value may contain an
 * apostrophe — which is why the human-authored label lives in a comment rather
 * than in the payload. Every field below is a base64url string, a URL, a
 * hostname, or a number, so the constraint holds by construction; keep it that
 * way when adding fields, and emit compact JSON so the value stays on one line.
 */

/** Current payload schema version. */
declare const CREDENTIAL_PAYLOAD_VERSION = 1;
type CredentialPayload = {
    v: number;
    baseUrl: string;
    rpId: string;
    origin: string;
    /** base64url, 32 bytes. */
    credentialId: string;
    /** base64url, 32 bytes. */
    userHandle: string;
    alg: CoseAlgorithm;
};
declare const CREDENTIAL_VARIABLE = "LWA_CREDENTIAL";
declare const CREDENTIAL_KEY_VARIABLE = "LWA_CREDENTIAL_KEY";
/** A `keystore:` URI instead of inline key material. */
declare function isKeystoreReference(value: string): boolean;
/**
 * Render the file.
 *
 * @param key - Base64 PKCS#8, or a `keystore:` URI.
 * @param comment - Free text for the leading comment; newlines are stripped.
 */
declare function formatCredentialFile(payload: CredentialPayload, key: string, comment?: string): string;
/** Read the two variables out of `.env` text, ignoring comments and other keys. */
declare function parseCredentialFile(text: string): {
    payload: string;
    key: string;
} | null;
/**
 * Validate a payload and refuse an unknown version.
 *
 * Refusing rather than ignoring an unrecognised `v` is deliberate: a later
 * version could add a load-bearing field — an audience, say — and a client that
 * guessed would authenticate against the wrong thing.
 */
declare function parseCredentialPayload(json: string): CredentialPayload;

/**
 * DPoP proof construction (RFC 9449).
 *
 * The proof is signed by the *same* key as the WebAuthn assertion, so the server
 * derives the expected thumbprint from the credential it already stores and keeps
 * no per-session key material. Safe because the two signed inputs cannot collide:
 * a JWS signing input is printable ASCII beginning `eyJ`, while a WebAuthn
 * assertion covers 69 bytes opening with a SHA-256 digest.
 *
 * Note that this signature is the *raw* `r ‖ s` form, not the DER the same key
 * emits for an assertion — see `ecdsa.ts`.
 */

declare function createDpopProof(input: {
    keyStore: MachineKeyStore;
    method: string;
    url: string;
    /** The session token this proof accompanies; hashed into `ath`. */
    accessToken: string;
    /** Most recent `DPoP-Nonce` from the server, when it demands one. */
    nonce?: string;
    now?: () => number;
}): Promise<string>;

/**
 * ECDSA signature re-encoding.
 *
 * One key signs in two incompatible formats, and mixing them up produces a
 * verification failure with no diagnostic:
 *
 * | Context            | Standard         | Encoding                        |
 * | ------------------ | ---------------- | ------------------------------- |
 * | WebAuthn assertion | COSE alg `-7`    | ASN.1 DER `SEQUENCE { r, s }`   |
 * | DPoP proof (JWS)   | RFC 7518 `ES256` | raw `r ‖ s`, 64 bytes           |
 *
 * WebCrypto's `ECDSA` sign returns the raw form, so the WebAuthn path converts
 * and the DPoP path does not. Ed25519 sidesteps this entirely — raw 64 bytes in
 * both — which is a decent reason to prefer it where the key store allows.
 */
/**
 * Convert a raw P-256 `r ‖ s` signature to ASN.1 DER.
 *
 * @param raw - Exactly 64 bytes, as WebCrypto's ECDSA sign returns for P-256.
 */
declare function rawSignatureToDer(raw: Uint8Array): Uint8Array;

/**
 * A `fetch` that authenticates itself with a software Passkey.
 *
 * One ceremony per session, then a DPoP proof per request. The long-lived key
 * never crosses the wire; only signatures over server-chosen material do.
 */

type MachineClientOptions = {
    payload: CredentialPayload;
    keyStore: MachineKeyStore;
    /** Endpoint paths, relative to `payload.baseUrl`. */
    endpoints?: {
        options?: string;
        verify?: string;
    };
    fetch?: typeof globalThis.fetch;
    /** Send `Authorization: DPoP` with a per-request proof. Defaults to `true`. */
    dpop?: boolean;
    now?: () => number;
};
declare class MachineClientError extends Error {
    readonly code: string;
    readonly status: number;
    constructor(code: string, message: string, status: number);
}
type Session = {
    token: string;
    expiresAt: number;
};
declare class MachineClient {
    #private;
    constructor(options: MachineClientOptions);
    /** Absolute URL for a path against the configured base. */
    url(path: string): string;
    /**
     * Run the ceremony and hold the resulting session.
     *
     * Called automatically by {@link fetch}; exposed so a long-running process can
     * warm up, or re-authenticate deliberately for a step-up operation.
     */
    authenticate(): Promise<Session>;
    /**
     * Call an API endpoint, authenticating first if needed.
     *
     * Retries a `401` **only** when the response positively identifies itself as an
     * authentication rejection made *before* the application handler ran:
     *
     * - an RFC 9449 nonce challenge — `WWW-Authenticate: DPoP …
     *   error="use_dpop_nonce"` — which the DPoP middleware emits instead of
     *   dispatching. The retry carries the supplied nonce and a fresh proof.
     * - a bare `WWW-Authenticate: DPoP` challenge with no nonce error, which means
     *   the session itself was refused; the retry re-authenticates first.
     *
     * Any other `401` is returned as-is. That matters more than it looks: a `401`
     * from the application's *own* handler carries no promise that the handler did
     * no work, and this client previously retried on any `401` that happened to
     * carry a `DPoP-Nonce` header — which authenticated responses legitimately do,
     * since the server rotates the nonce forward on success. A `POST` that failed
     * authorization after taking effect would have been sent twice. HTTP status is
     * not evidence of non-execution; the challenge header is.
     *
     * A retried request re-sends `init` unchanged, so a one-shot body (a
     * `ReadableStream`) cannot be replayed — pass `bodyFactory` to rebuild it, or the
     * retry is refused rather than silently sending a consumed body. Strings, byte
     * arrays and other reusable bodies need nothing.
     */
    fetch(path: string, init?: RequestInit & {
        /** Rebuilds a one-shot body for a retry. Required for stream bodies. */
        bodyFactory?: () => BodyInit;
    }): Promise<Response>;
}

export { CREDENTIAL_KEY_VARIABLE, CREDENTIAL_PAYLOAD_VERSION, CREDENTIAL_VARIABLE, type CoseAlgorithm, type CredentialPayload, EDDSA, ES256, MachineClient, MachineClientError, type MachineClientOptions, type MachineKeyStore, type SoftwareAssertionResponse, type SoftwareCredential, type SoftwareRegistrationResponse, concat, createAssertionResponse, createDpopProof, createRegistrationResponse, decodeBase64, decodeBase64Url, encodeBase64, encodeBase64Url, formatCredentialFile, generateKeyStore, importKeyStore, isKeystoreReference, parseCredentialFile, parseCredentialPayload, randomBytes, rawSignatureToDer, sha256, utf8 };
