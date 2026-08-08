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

# Architecture: passkey-gated, proof-of-possession API access

Your adversarial premise is the correct starting point:

> A party controlling a credential’s private key can produce every signature that key is capable of producing.

Authentication therefore proves **control of a key**, not that the controller is honest, human, understood a prompt, or followed the intended software path. The authorization server must make every important decision from server-controlled state and cryptographically verified inputs.

That does not make WebAuthn broken. It means WebAuthn has several distinct assurance properties:

1. **Core cryptographic assurance:** possession of the registered private key.
2. **Freshness:** possession was demonstrated for a server-generated challenge.
3. **RP/origin binding:** meaningful when the browser/client platform is trusted to construct those values correctly.
4. **User presence or verification:** meaningful when the relying party trusts the authenticator to report them truthfully.
5. **Hardware protection or non-exportability:** meaningful only when supported by sufficiently trustworthy attestation and authenticator policy.

The WebAuthn specification is explicit that authenticator-data trust depends on the relying party’s assessment of the authenticator; an authenticator embedded in the client may provide bindings “no more trustworthy than the client data.” It also warns that malicious code executing on an allowed RP origin can invalidate WebAuthn’s guarantees. ([W3C][1])

## What a WebAuthn assertion actually signs

A WebAuthn assertion is not normally a raw signature over an arbitrary application string. It is effectively:

```text
signature =
    Sign(
        credential_private_key,
        authenticatorData || SHA-256(clientDataJSON)
    )
```

`clientDataJSON` contains, among other things:

```json
{
  "type": "webauthn.get",
  "challenge": "<server challenge>",
  "origin": "https://auth.example.com",
  "crossOrigin": false
}
```

`authenticatorData` contains:

```text
rpIdHash
flags: UP, UV, BE, BS, ED, ...
signCount
extensions
```

The relying party verifies the challenge, origin, RP ID hash, applicable flags, and signature. ([W3C][1])

This fixed signing format has an important architectural consequence:

> A passkey private key generally cannot directly produce a DPoP JWT, `private_key_jwt`, or RFC 9421 HTTP Message Signature.

The authenticator exposes “make a WebAuthn assertion,” not “sign arbitrary bytes.” Therefore, use the passkey assertion to authorize or bind a separate API proof-of-possession key.

## Recommended system

```text
                  ┌────────────────────────┐
                  │ Credential Registry    │
                  │                        │
                  │ - WebAuthn credentials │
                  │ - API workload keys    │
                  │ - trust/assurance tier │
                  └───────────┬────────────┘
                              │
┌──────────────┐    challenge │    ┌─────────────────────────┐
│ API Client   │◄─────────────┼────│ Authorization Challenge │
│              │              │    │ Endpoint                │
│ passkey      │──assertion───┼───►│                         │
│ + DPoP key   │              │    │ WebAuthn verification   │
└──────┬───────┘              │    │ policy + authorization  │
       │                      │    └────────────┬────────────┘
       │                                      authorization code
       │                                           │
       │                               ┌───────────▼───────────┐
       │             DPoP proof        │ Token Endpoint        │
       └──────────────────────────────►│                       │
                                      │ DPoP-bound tokens     │
                                      └───────────┬───────────┘
                                                  │
                                      access token + DPoP proof
                                                  │
                                      ┌───────────▼───────────┐
                                      │ Resource Servers       │
                                      │ replay and policy      │
                                      │ enforcement            │
                                      └───────────────────────┘
```

The system supports three credential classes and does not confuse their assurances:

| Credential class    | Meaning                                                                                                                                      |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `webauthn-user`     | A genuine user-facing WebAuthn credential. UP, UV, origin and attestation may be considered according to policy.                             |
| `api-pop`           | A software, HSM, TPM or KMS-held API key. It proves key possession only. It makes no claim about a human, browser origin or biometric check. |
| `attested-workload` | An API key whose workload, hardware or key storage provenance has been separately attested.                                                  |

Never allow an `api-pop` credential to acquire `webauthn-user` assurance merely by constructing an assertion with its UV or UP bits set.

## 1. Credential registration

### Real passkey registration

Use a normal WebAuthn registration ceremony. The server verifies the registration challenge, expected origin and RP ID, obtains the credential ID and public key, and optionally evaluates attestation.

Store:

```text
credential_id
principal_id / account_id
credential_class = webauthn-user
COSE public key
algorithm
RP ID
allowed origins
UV policy
attestation trust tier, if used
AAGUID, if retained
backup-eligible and backup-state values
last signCount, advisory only
status: active / revoked / suspended
scope ceiling
created_at / last_used_at
```

### Headless API registration

Do not make a daemon pretend that it performed a biometric check. Give API clients an explicit public-key enrollment path:

1. An administrator or account owner authorizes enrollment, normally using their real passkey.
2. The API client generates a key in its HSM, TPM, KMS or local keystore.
3. It submits its public key and proof of possession.
4. The server registers it as `api-pop` or `attested-workload`.
5. The server gives it a stable `credeial_id` or `key_id`.

It is technically possible for software to construct WebAuthn-shaped registration and assertion bytes. With no trusted attestation, however, the relying party cannot infer that the key was used through a real browser, that a human was present, or that the reported flags are truthful. Such a credential should therefore be classified as pure public-key proof of possession, not as user-verified WebAuthn.

## 2. Challenge initiation

The client first generates or selects an API-session proof key, `K_api`, such as a P-256 DPoP key.

It then requests authorization:

```http
POST /v1/authorization-challenges
Content-Type: application/json
```

```json
{
  "client_id": "client-123",
  "credential_id": "cred-456",
  "audience": "https://payments-api.example.com",
  "scope": ["payments.read", "payments.create"],
  "dpop_jkt": "thumbprint-of-K_api",
  "authorization_details": {
    "account": "acct-789",
    "maximum_amount": "5000.00",
    "currency": "CAD"
  }
}
```

The server:

1. Resolves the credential and principal.
2. Applies the client’s scope ceiling and authorization policy.
3. Generates an unpredictable 32-byte challenge.
4. Stores the complete requested context server-side.
5. Binds the transaction to the DPoP key thumbprint.
6. Returns WebAuthn request options.

Example transaction record:

```text
transaction_id
SHA-256(challenge)
credential_id
principal_id
client_id
audience
approved scopes / authorization details
dpop_jkt
purpose
operation_hash, if applicable
expires_at
state = unused
```

The challenge should be an opaque random value. Do not rely on the client to faithfully copy authorization context into something it signs; the server already has the authoritative context. WebAuthn specifically requires server-generated unpredictable challenges and recommends retaining them server-side rather than relying on client behavior. ([W3C][1])

Response:

```json
{
  "transaction_id": "tx-abc",
  "expires_in": 120,
  "publicKey": {
    "challenge": "base64url-random-challenge",
    "rpId": "auth.example.com",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "base64url-credential-id"
      }
    ],
    "userVerification": "required"
  }
}
```

## 3. Passkey assertion redemption

The client obtains an assertion and submits it together with a DPoP proof made by `K_api`:

```http
POST /v1/authorization-challenges/tx-abc
DPoP: <proof-signed-by-K_api>
Content-Type: application/json
```

```json
{
  "credential_id": "cred-456",
  "clientDataJSON": "...",
  "authenticatorData": "...",
  "signature": "...",
  "userHandle": "..."
}
```

The authorization server performs all of the following:

1. Find the active credential by credential ID.
2. Verify `clientDataJSON.type == "webauthn.get"`.
3. Verify exact equality with the stored challenge.
4. Verify the origin against an exact allowlist.
5. Verify `rpIdHash`.
6. Verify the assertion signature.
7. For `webauthn-user`, require UP and enforce UV according to policy.
8. Check the transaction’s expiry.
9. Verify the accompanying DPoP proof and match its key thumbprint to the transaction’s stored `dpop_jkt`.
   10.e-evaluate current account, credential, scope and risk policy.
10. Atomically change the transaction from `unused` to `consumed`.
11. Return a short-lived, single-use authorization code bound to the same DPoP key.

The atomic transition is important: signature verification followed by a non-atomic “mark used” operation permits concurrent replay against multiple authorization-server instances.

A July 2026 IETF Internet-Draft for first-party applications describes a closely related sequence: receive a passkey challenge, submit the signed challenge, receive an authorization code, and exchange that code at the token endpoint. The same draft recommends binding the authorization session, authorization code and subsequent token requests to a DPoP key. It remains an Internet-Draft rather than a finalized RFC. ([IETF Datatracker][2])

## 4. Token issuance and API access

The client exchanges the code at the ordinary token endpoint, again proving possession of `K_api`:

```http
POST /oauth/token
DPoP: <proof-signed-by-K_api>
Content-Type: application/x-www-form-urlencoded
```

The access token is sender-constrained:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-or-service-principal",
  "client_id": "client-123",
  "aud": "https://payments-api.example.com",
  "scope": "payments.read payments.create",
  "amr": ["webauthn"],
  "acr": "urn:example:assurance:webauthn-uv",
  "cnf": {
    "jkt": "thumbprint-of-K_api"
  },
  "iat": 1786120000,
  "exp": 1786120300
}
```

Every resource request includes both the access token and a DPoP proof. DPoP proofs carry a unique `jti`, HTTP method, target URI and creation time; proofs accompanying access tokens also contain `ath`, a hash of the access token. The resource server verifies that the proof’s public key matches the key to which the token was bound. ([RFC Editor][3])

Use:

- Short-lived access tokens, such as 5–10 minutes.
- Rotating refresh tokens bound to the same DPoP key.
- A replay cache for DPoP `jti` values.
- Server-provided DPoP nonces for high-risk endpoints or where pre-generation is a concern.

That last control directly addresses the hostile-client argument. RFC 9449 explicitly observes that even a legitimate but malicious user could pre-generate DPoP proofs for future use. Unpredictable server-provided nonces prevent this because the client cannot sign a future proof until the server supplies the nonce. ([RFC Editor][3])

DPoP deliberately covers only a limited portion of the HTTP request by default. It binds the method, URI and token, but not normally the request body. For body-sensitive operations, bind a content digest through the authorization transaction or use HTTP Message Signatures, which provide a standard mechanism for signing selected HTTP components. ([RFC Editor][3])

## What state belongs on the client?

A WebAuthn credential source normally contains the private key, credential ID, RP ID, user handle for discoverable credentials, and optional UI metadata. The relying party stores the public key and corresponding credential record. ([W3C][1

For this architecture:

| Location                              | State                                                                                                                                            |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Authenticator/passkey provider        | Private key, credential ID, RP ID, user handle where applicable, optional signature counter and synchronization metadata.                        |
| API client application                | `client_id`, DPoP private key, refresh token, current authorization transaction, latest server-issued DPoP nonce.                                |
| Authorization server                  | Credential public key and class, account binding, trust policy, challenge transactions, authorization codes, revocation state and audit history. |
| Resource server/shared security layer | DPoP replay cache, accepted token issuers and keys, audience/scope policy, optionally recent server nonces.                                      |

### The counter

Do **not** make a client counter security-critical.

WebAuthn’s `signCount`:

- Is optional.
- May remain zero permanently.
- Is intended as a possible clone-detection signal.
- Can produce ambiguous results because of parallel use, malfunction or multiple copies.
- Is not the mechanism that provides freshness or replay prevention. ([W3C][1])

For API security, use:

```text
server challenge + expiry + atomic single-use state
```

and, for normal requests:

```text
DPoP jti replay cache + short proof lifetime + optional server nonce
```

A client-controlled monotonically increasing counter is particularly unhelpful under your threat model: the hostile client can choose any value. A hardware-protected signed monotonic counter might be a useful additional risk signal, but it is still not a replacement for a server nonce.

## Direct passkey authorization of individual API calls

For rare, high-value operations, the passkey can authorize the exact operation rather than merely issuing a session token.

### Begin operation

```http
POST /v1/operation-authorizations
```

```json
{
  "credential_id": "cred-456",
  "operation": {
    "method": "POST",
    "resource": "/v1/transfers",
    "body_sha256": "base64url-digest",
    "idempotency_key": "payment-987",
    "source_account": "acct-1",
    "destination_account": "acct-2",
    "amount": "250.00",
    "currency": "CAD"
  }
}
```

The server validates the proposed operation and stores its canonical semantic representation against a random challenge.

### Sign and execute

The client obtains a WebAuthn assertion for that challenge, then submits both the assertion and operation. The server:

1. Reconstructs the operation’s canonical form.
2. Checks it against the stored transaction.
3. Verifies the assertion.
4. Atomically consumes the transaction.
5. Executes the operation under the same transaction or idempotency boundary.

This prevents a captured asseron for “transfer CAD 250 to account A” from authorizing a different transfer.

It still does **not** prove that a human read or understood the transaction. A malicious client can display one thing and request a signature for another. A claim that the user saw specific transaction details requires a trusted display or another independently trusted confirmation path, not merely a WebAuthn signature.

Because this flow adds a challenge round trip and ordinarily a user-presence operation for every call, reserve it for step-up authorization, key enrollment, privilege escalation, payment approval or service-key rotation.

## Security invariants

The implementation should make these properties explicit:

1. **Possession is not intent.** A valid signature says that the credential was exercised, not that its holder is trustworthy.
2. **Authorization is always server-side.** The client never chooses its effective scopes, tenant, audience or transaction limits.
3. **Freshness is server-controlled.** Client timestamps and counters are secondary inputs only.
4. **Transactions are context-bound.** A challenge maps to one principal, credential, audience, DPoP key and authorization request.
5. **Challenges and codes are single-use.** Consumption is atomic across the cluster.
6. **Tokens are sender-constrained.** Theft of an access or refresh token alone is insufficient.
7. **Credential classes cannot be confused.** A software API credential can never assert biometric, human-presence or phishing-resistant assurance.
8. **Origin and UV are conditional properties.** They are considered only for actual WebAuthn clients and authenticators that meet the configured trust policy.
9. **Compromise is expected operationally.** Support rapid revocation, key rotation, multiple credentials, anomaly detection, quotas and narrow scopes.
10. **TLS remains mandatory.** Message signatures supplement transport security; they do not replace confidential and authenticated transport.

## Assessment of the quoted claims

| Claim                                                | Assessment                                                                                                                                                                                                                                                                                          |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| “Passkeys do not replace API client secrets.”        | Too categorical. A public-key credential can absolutely replace a symmetric client secret. A WebAuthn passkey is simply not a drop-in `client_secret` field because it exposes a structured assertion operation rather than arbitrary signing.                                                      |
| ��Passkeys always require biometrics or a PIN.”      | False. WebAuthn allows user verification to be `required`, `preferred` or `discouraged`. However, normal WebAuthn assertion verification does require the UP flag, so a conforming browser ceremony remains user-presence-oriented even when biometric/PIN verification is not required. ([W3C][1]) |
| “They are unusable for headless JavaScript servers.” | Too absolute. A headless process can own a key, use an external signer, construct a WebAuthn-shaped proof, or be delegated a workload key through a passkey-gated flow. What it cannot honestly claim, without an appropriate trusted authenticator, is human presence or biometric verification.   |
| “Servers must continue using client secrets.”        | False. Standard public-key alternatives include JWT client authentication and mTLS; DPoP can sender-constrain issued tokens. ([RFC Editor][4])                                                                                                                                                      |

The clean formulation is:

> Use genuine passkeys for user authentication, administrative control and delegation. Use an API proof key for repeated requests. Bind the two cryptographically during authorization, and treat a fully headless “passkey” implementation as a public-key workload credential with no human-presence assurances.

That architecture remains secure even when the client is assumed hostile: the client may sign anything it is asked to sign, but it cannot invent an unused server challenge, alter the server’s stored authorization context, reuse a consumed transaction, expand its scope, or use a stolen sender-constrained token without the associated API key.

[1]: https://www.w3.org/TR/webauthn-3/ 'Web Authentication: An API for accessing Public Key Credentials - Level 3'
[2]: https://datatracker.ietf.org/doc/draft-ietf-oauth-first-party-apps/ 'draft-ietf-oauth-first-party-apps-04 - OAuth 2.0 for First-Party Applications'
[3]: https://www.rfc-editor.org/rfc/rfc9449.html 'RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)'
[4]: https://www.rfc-editor.org/rfc/rfc7523.html?utm_source=chatgpt.com 'RFC Editor'
