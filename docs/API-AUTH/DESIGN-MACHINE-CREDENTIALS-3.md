# API via Passkeys

Design an architecture to support API clients via Passkeys, which are simply signatures over a
challenge + some other data, with some storage of on the client (counter? anything else?); Claims
such as the following are demonstrably false, and any security assumptions surrounding Passkeys that
assume some specific behaviour on part of the putative Passkey client/owner are vaccuous: a hostile
holder of a Passkey secret key can be assumed to do anything, so if WebAuthn's security assumptions
rest on assuming the Passkey client did or did not do something, then WebAuthn is broken:

Passkeys replace user passwords and traditional credentials with public-key cryptography, but they
do not replace API client secrets for server-to-server communication. Passkeys require a user
interface and an authenticator (like a phone or hardware key) to approve a cryptographic challenge
via biometrics or a PIN, making them unusable for headless JavaScript servers communicating directly
with external APIs.Understanding the Core DifferenceAPI Client Secrets: Used for machine-to-machine
(M2M) or backend-to-backend authentication. No human user is present to touch a fingerprint scanner
or click a prompt.Passkeys: Designed for end-user authentication via the WebAuthn API, relying on
physical devices and biometrics.When to Use Each in a JS EnvironmentFor Browser-to-Server (End
Users): Use passkeys instead of passwords to let users log into your JavaScript-driven web
application securely.For Server-to-API (Backend Services): Continue using client secrets, signed
JWTs, or mutual TLS (mTLS) because servers cannot prompt a user for a biometric touch.If you are
trying to secure communication between a frontend client and a backend server, or a Node.js server
and a third-party API, let me know and I can show you the correct authentication pattern for that
specific workflow.

# Summary

**Passkeys (and WebAuthn credentials more generally) are public-key signatures over a challenge plus authenticator data.** The private key is held by an “authenticator”; the relying party stores only the public key (plus metadata). A signature counter (`signCount`) is optionally maintained and returned in authenticator data to help detect clones. Everything else—user presence (UP), user verification (UV), origin binding, RP ID hashing, attestation—is protocol and policy layered on top of that core.

A hostile holder of the private key can do _anything_ the legitimate holder can do. Any security claim that rests on the client/authenticator “behaving” (always requiring a biometric, never exporting the key, always incrementing the counter honestly, never signing outside a UI prompt, etc.) is vacuous once the key material is under attacker control. Hardware-backed authenticators (TPM, Secure Enclave, FIDO2 security keys with non-exportable keys) raise the bar against extraction; pure software keys do not. WebAuthn is not “broken” for its intended phishing-resistant _user_ authentication use-case when the authenticator actually enforces the flags and non-exportability; extending the same assumptions to arbitrary software clients is where the model fails.

The quoted claims are therefore incorrect on the cryptography: the same primitives _can_ authenticate headless API clients (including Node.js servers). What cannot be done is a direct, unmodified WebAuthn ceremony that demands a user gesture inside a headless process. The correct approach is a unified credential model that re-uses the signature + counter core for both interactive Passkeys and non-interactive API clients, relaxing only the UI-dependent flags.

## Architecture: Unified Passkey-Style Credentials for Users _and_ API Clients

### 1. Credential Model (server-side store)

Store a single table/collection of credentials:

- `credentialId` (opaque, high-entropy)
- `publicKey` (COSE_Key or JWK; prefer ES256 / Ed25519)
- `signCount` (last observed value; 0 if the authenticator never increments)
- `type` (`webauthn-passkey` | `api-passkey`)
- `subject` (user ID or client/application ID)
- `algorithm`, `transports` / `aaguid` (optional), attestation data (optional), status (active/revoked), created/updated timestamps

The same verification path can handle both types. For `webauthn-passkey` enforce UP/UV/origin/RP-ID as usual. For `api-passkey` treat UP/UV as optional (or always false) and accept a simplified or fully-emulated authenticator data structure.

### 2. Client-side storage (the “authenticator”)

- Private key held non-exportably when possible (OS keychain, TPM/PKCS#11, cloud HSM/KMS, or encrypted at rest with a machine-bound secret).
- Local `signCount` (uint32/64, start at 0, increment on every successful signature generation).
- `credentialId`.
- Optional metadata (algorithm, creation time).

A pure software implementation in Node.js is sufficient for many API clients; the security then reduces to protection of that private key exactly as with any other asymmetric client credential.

### 3. Registration

**API client path (headless-friendly):**

1. Client generates a key pair.
2. Bootstrap authentication (one-time client secret, mTLS, admin approval, or existing OAuth client credentials).
3. Client sends `{publicKey, algorithm, optional attestation, initialSignCount: 0}` to a registration endpoint.
4. Server stores the credential, returns `credentialId`.

**User path:** ordinary WebAuthn `navigator.credentials.create()` / platform Credential Manager; server verifies attestation and stores the same way, marking `type = webauthn-passkey`.

Attestation is useful when you want to know the authenticator class (platform, roaming, software) but is not required for the signature model itself.

### 4. Authentication / Assertion

Two complementary modes; both are just signatures.

**A. Challenge-response (ceremony style, good for login or high-value operations)**

- Client requests a fresh random challenge (and optional state).
- Client constructs data to be signed. Minimal form:

  ```
  signed = challenge || credentialId || signCount || timestamp || optional-scope
  ```

  Or a WebAuthn-compatible shape (clientDataJSON + authenticatorData with flags set appropriately for the type, RP-ID hash or a fixed API identifier, incremented `signCount`).

- Client signs with the private key and returns `{credentialId, signature, signCount, clientDataJSON?, authenticatorData?}`.
- Server:
  - looks up public key,
  - verifies signature,
  - checks `signCount > storedSignCount` (or `== 0` if the authenticator never increments),
  - updates stored counter,
  - issues a short-lived access token / session if desired.

**B. Per-request signing (preferred for ongoing API traffic)**  
Use RFC 9421 HTTP Message Signatures (asymmetric algorithms) or an equivalent canonical request signature that includes:

- HTTP method + path + selected headers + body hash
- timestamp (narrow acceptance window)
- nonce or the current `signCount`
- `credentialId` / key id

The signature is carried in `Signature` / `Signature-Input` headers (or custom headers). Server verifies the signature against the registered public key, enforces monotonicity of the counter (or uniqueness of the nonce), and rejects replays. This is exactly analogous to `private_key_jwt` client authentication or AWS SigV4-style signing, but with an explicit counter for clone detection.

After a successful assertion you may mint a short-lived bearer token so that every subsequent call need not perform a public-key operation; for the highest assurance keep per-request signatures.

### 5. Counter semantics and clone detection

- Authenticators that implement a counter increment it on every assertion and return the new value.
- Server stores the highest value seen. A later assertion with a lower or equal non-zero counter is evidence of a clone (or a race / malfunction).
- Many synced Passkey providers deliberately return `signCount = 0` forever; the mechanism is therefore ineffective for those credentials. For device-bound or pure API credentials you control, enforce strict increase.
- The counter only detects _divergent_ use of a cloned key; an attacker who solely possesses the key can simply keep incrementing. It is a useful signal, not a hard security boundary.

### 6. Implementation sketch for a headless JS (Node) client

```js
// Registration (once)
const { publicKey, privateKey } = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  true,
  ['sign', 'verify'],
);
// export public key, register with server, store privateKey + credentialId + signCount=0 securely

// Assertion
async function signRequest(challengeOrCanonicalRequest) {
  const counter = ++localSignCount;
  const data = new TextEncoder().encode(
    `${challengeOrCanonicalRequest}|${credentialId}|${counter}|${Date.now()}`,
  );
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data);
  return { credentialId, signature: bufToB64url(signature), signCount: counter };
}
```

Server verification is ordinary ECDSA/EdDSA verify + counter check. Libraries that aeady implement WebAuthn assertion verification can be reused with relaxed flag checks for the `api-passkey` type.

### 7. Security model (honest version)

- **Possession of the private key ≡ ability to authenticate.** There is no additional “user intent” for a headless client.
- Hardware non-exportability + audited key usage is the only practical way to raise the cost of key theft.
- Replay protection comes from the challenge / timestamp + counter / nonce, not from any client-side ritual.
- Origin / RP-ID binding is relevant for browser Passkeys; for pure API clients bind to a logical audience or API identifier instead.
- Compromise of the client process or the storage that holds the private key is fatal—exactly as with any other client secret or private key. The architecture does not pretend otherwise.

This design lets the _same_ server-side credential store and verification logic serve interactive WebAuthn Passkeys _and_ headless API clients. The UI/biometric requirement is an artifact of the user-facing WebAuthn ceremony, not of the underlying signature scheme. Consequently the claim that Passkeys are unusable for server-to-server / headless JavaScript clients is false; only the unmodified browser WebAuthn API surface is unusable in that environment.
