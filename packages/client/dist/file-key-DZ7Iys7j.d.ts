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
/**
 * Read the two variables out of `.env` text, ignoring comments and other keys.
 *
 * Refuses a file larger than {@link MAX_FILE_BYTES}, and refuses either variable
 * appearing twice: with two assignments a shell would take the last and a careless
 * reader the first, so "which key is this?" would have two answers.
 */
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

export { type CredentialPayload as C, EDDSA as E, type MachineKeyStore as M, CREDENTIAL_PAYLOAD_VERSION as a, type CoseAlgorithm as b, ES256 as c, CREDENTIAL_KEY_VARIABLE as d, CREDENTIAL_VARIABLE as e, formatCredentialFile as f, generateKeyStore as g, isKeystoreReference as h, importKeyStore as i, parseCredentialFile as j, parseCredentialPayload as p };
