# Consensus across the three API-auth designs

> **Superseded design note.** Written before the implementation and not updated since;
> where it disagrees with [`docs/API-AUTH.org`](../../API-AUTH.org), that document is
> right. See [the history index](README.md) for what each of these was.

Reviews `DESIGN-MACHINE-CREDENTIALS.md` (1), `-2.md` (2), and `-3.md` (3), and answers the
question of whether the "passkey at session start, cheap credential thereafter" pattern is
already standardised.

Short version: the three documents agree on everything that matters and differ on how much
machinery to build. The pattern the user is drawn to is not only well thought through, it
is published as an IANA-registered HTTP authentication scheme, and the FIDO Alliance names
it as the intended complement to passkey authentication. The developing draft is real but
is the wrong thing for this project to implement.

## Where all three agree

1. **Possession of the key is the whole of the authentication.** All three start from the
   adversarial premise and reach the same place. (1) §2.2 "a signature proves possession of
   a key; nothing else in the assertion is evidence"; (2) "authentication proves control of
   a key, not that the controller is honest, human, understood a prompt, or followed the
   intended software path"; (3) "possession of the private key ≡ ability to authenticate."
2. **The quoted claims are false on the cryptography.** Unanimous. All three also agree on
   the precise residue of truth: what a headless client cannot honestly claim is _human
   presence_, and that is a claim about meaning, not a limit on capability.
3. **Credential class must be a server-owned field.** (1) `kind`; (2) `credential_class` ∈
   {`webauthn-user`, `api-pop`, `attested-workload`}; (3) `type` ∈ {`webauthn-passkey`,
   `api-passkey`}. Three independent designs invented the same column, which is a strong
   signal for issue #11. (2) states the invariant most sharply: "never allow an `api-pop`
   credential to acquire `webauthn-user` assurance merely by constructing an assertion with
   its UV or UP bits set."
4. **Freshness is server-controlled.** Random, unpredictable, single-use, expiring
   challenge, held server-side. Never derived from client state. (2) adds the point the
   others miss: consumption must be **atomic**, or concurrent replay against multiple
   server instances defeats it.
5. **The signature counter is not a security boundary.** (1) "not a control against a
   hostile holder"; (2) "do not make a client counter security-critical"; (3) "a useful
   signal, not a hard security boundary."
6. **Origin / RP-ID binding is meaningless for a machine**; bind to a logical audience
   instead. All three.
7. **Two phases: an expensive asymmetric ceremony at session start, something cheap for
   ongoing traffic.** All three propose exactly this, independently. This is the thing the
   user picked out, and it is the real consensus.
8. **Hardware custody is the only mitigation for key theft.** TPM, Secure Enclave, KMS,
   HSM, PKCS#11. All three, and all three say software keys reduce to "as good as any other
   private key on that host."
9. **Reserve a fresh assertion for step-up.** (1) §7 "Step up"; (2) "Direct passkey
   authorization of individual API calls"; (3) mode A "good for login or high-value
   operations." (2) is the most careful here: binding the operation's canonical form to the
   challenge stops a captured assertion for "transfer 250" authorizing a different
   transfer — while still not proving a human read anything.
10. **Machine registration must be authorized out-of-band** — admin approval, a real
    passkey, or a one-time bootstrap secret. All three refuse to let a machine credential
    self-enroll.

## Where they disagree

### A. Can the passkey key itself sign per-request proofs?

(2) says no, and makes it load-bearing: _"a passkey private key generally cannot directly
produce a DPoP JWT, `private_key_jwt`, or RFC 9421 HTTP Message Signature. The
authenticator exposes 'make a WebAuthn assertion,' not 'sign arbitrary bytes.'"_ (1) and (3)
assume it can, because their authenticator is software they wrote.

Both are right in their own domain. For a real passkey — browser plus platform
authenticator, iCloud Keychain, a YubiKey — (2) is correct: the only exposed operation is
`navigator.credentials.get()`, and `clientDataJSON` is written by the browser. For a
software authenticator it is `crypto.subtle.sign` and there is no restriction.

**Resolution: use two keys regardless.** (2) reaches the right answer via a reason that
only holds for real passkeys, but two further reasons hold universally:

- **Hardware economics.** The whole argument for this design is that the credential key
  lives in a TPM or a KMS. You do not want a KMS round trip, its latency, its per-call
  cost, or its quota on every HTTP request. A session key in process memory is free.
- **One architecture.** The human-in-a-browser case _requires_ the split. Building the
  split once means the machine path and the human path are the same protocol, rather than
  two.

So: long-lived credential key in hardware, signs at session start only; ephemeral session
key in memory, signs each request. If someone does share one software key across both, note
that the two signed payloads cannot collide — a JWT signing input is printable ASCII, a
WebAuthn signed blob opens with 32 bytes of SHA-256 output — so the domain separation is
structural rather than lucky. It is still the wrong choice for a hardware-held key.

### B. What carries the session?

| Doc | Proposal                                                               |
| --- | ---------------------------------------------------------------------- |
| 1   | The package's existing opaque session token, as a bearer.              |
| 2   | DPoP-bound access token, issued by a full OAuth authorization server.  |
| 3   | Either a short-lived bearer token, or per-request RFC 9421 signatures. |

**Resolution: DPoP's mechanism applied to the existing opaque token.** See below — this is
the substance of the recommendation.

### C. Counter: constant zero or strict increase?

(1) recommends a constant `0` and gives the operational reason: restore a host from a
backup older than its last authentication and a strict counter goes backwards, permanently
rejecting an unattended machine. (3) recommends enforcing strict increase "for device-bound
or pure API credentials you control." (2) declines to make it security-critical at all.

**Resolution: never gate authentication on it; log divergence as a signal.** (3)'s case is
not unreasonable for a single instance with durable storage, and (1) concedes as much. But
"credentials you control" is exactly the situation where you also control the deployment,
and trading a 3 a.m. lockout for a signal you were never going to act on automatically is a
bad trade. Record counter regression as an anomaly event; do not fail the request on it.

### D. How much machinery?

(1) is a minimal additive change to this package: one column plus plumbing. (2) is an OAuth
authorization server: challenge endpoint, transaction records, authorization codes, token
endpoint, JWT access tokens with `cnf`/`jkt`, scopes, audiences, `authorization_details`.
(3) sits between.

This is the only genuine decision, and it is a project-fit question rather than a security
one. Both (1) and (2) are internally correct.

## The standards answer

The instinct is right. Two published RFCs and one draft cover this, and the FIDO Alliance
has written down the division of labour explicitly.

### Published and directly applicable

**RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP).** `DPoP` is a registered
HTTP authentication scheme in the IANA HTTP Authentication Schemes registry, so this is
"baked into the protocol" in the literal sense the question asks for:

```http
GET /api/reports HTTP/1.1
Authorization: DPoP <session-token>
DPoP: <compact JWS>
```

The proof is a JWT with header `{"typ":"dpop+jwt","alg":"ES256","jwk":{…public key…}}` and
claims `jti`, `htm` (method), `htu` (target URI, no query or fragment), `iat`, and `ath`
(base64url SHA-256 of the accompanying token). The server verifies the proof's
self-signature with the embedded `jwk`, computes its RFC 7638 thumbprint, and checks it
against the thumbprint bound to the token.

Two details make this a very good fit for the threat model in these documents:

- **§8 server-provided nonces** exist precisely because "even a legitimate but malicious
  user could pre-generate DPoP proofs for future use." The server issues a nonce via
  `DPoP-Nonce`, demands one with `WWW-Authenticate: DPoP error="use_dpop_nonce"`, and the
  client cannot sign a future proof before the server supplies it. (2) already spotted
  this; it is the one control in the whole design aimed squarely at a hostile-but-legitimate
  key holder.
- **The server never issues a JWT.** It only verifies one, using a key the client embedded.
  No signing key, no JWKS endpoint, no key rotation, no `kid` management. This is the
  property that makes DPoP cheap to adopt and an OAuth AS expensive.

**RFC 9421 — HTTP Message Signatures.** The `Signature` / `Signature-Input` mechanism (3)
prefers. DPoP deliberately covers only method, URI, token and time — not the body. Where
body integrity through an intermediary matters, 9421 plus RFC 9530 `Content-Digest` is the
standard answer. It is the right _option_, not the right _default_: more canonicalization
surface, more ways for a proxy to break it, and not an authentication scheme.

### The developing draft

**`draft-ietf-oauth-first-party-apps-04`**, dated 1 July 2026, status **"WG Consensus:
Waiting for Write-Up"** — working-group consensus reached, awaiting shepherd write-up, not
yet an RFC. This is the reference in (2), and (2) characterises it accurately.

It defines an **Authorization Challenge Endpoint**: the client POSTs (`client_id`, `scope`,
`auth_session`, `code_challenge`, `response_type=code`), and receives either
`authorization_code` or an error — `insufficient_authorization`, `invalid_session`,
`redirect_to_web` — iterating until authorization is sufficient, then exchanges the code at
the ordinary token endpoint. Appendix A.1 is the passkey flow: collect username → get
challenge → sign with the passkey → submit signature and credential ID → receive
authorization code → exchange for tokens. §9.5.1 says DPoP authorization-code binding
SHOULD be used; §9.6.1 says the opaque `auth_session` SHOULD be bound to the DPoP key too.

Worth knowing before treating it as a specification to implement: **Appendix A.1 is a
narrative sketch with no worked HTTP examples.** The detailed request/response examples in
the draft cover the username + OTP flow (Appendix B.3), not passkeys. There is no
WebAuthn profile to conform to — only a shape to imitate.

### The authoritative confirmation

The FIDO Alliance white paper _DBSC/DPoP as Complementary Technologies to FIDO
Authentication_ states the division of labour outright: FIDO handles initial authentication
and defeats phishing and credential stuffing; DBSC and DPoP address the "lift and shift"
attack on bearer tokens afterwards. Their comparison table has passkeys covering remote
phishing and credential stuffing but **not** token theft, and DBSC/DPoP covering token theft
but not the initial vectors. Session hijacking is called "a growing initial attack vector":
once attackers are thwarted at login they turn to stealing and replaying bearer tokens.

So "reserve the passkey for start of session, then use something else per request" is not a
workaround for passkeys being awkward. It is the architecture FIDO intends, and the
something-else is specified.

### Ruled out on purpose

**RFC 9729 — the Concealed HTTP Authentication Scheme.** Genuinely an HTTP-native
asymmetric auth scheme: key ID plus key pair, server maps key IDs to public keys, signature
in `Authorization`. It looks like an exact match and is not, for two reasons. Its proofs
are bound to the TLS connection through a keying-material exporter, not to individual
requests — every request on a connection carries an identical `Authorization` header, which
the RFC itself flags as replayable between security contexts multiplexed on one connection.
And it needs TLS exporter access, which a server behind a terminating load balancer or CDN
does not have. Named here so it is excluded deliberately rather than overlooked.

**RFC 8120 `Mutual`** is registered and effectively unused. **`private_key_jwt` (RFC 7523)**
and **mTLS (RFC 8705)** are the OAuth-native peers of this design; they are alternatives to
the whole approach rather than components of it.

## Recommendation

Implement the **pattern** from the draft and the **mechanism** from RFC 9449. Do not
implement the draft.

### What to build

Keep (1) as the credential layer — it is the part that closes issue #11 — and add DPoP as
an optional transport binding on top of the session token that already exists:

1. **One column:** `localwebauthn_sessions.dpop_jkt TEXT` (nullable). Null means the
   session is an ordinary bearer, which is today's behaviour.
2. **Bind at authentication.** `verifyAuthentication` accepts an optional
   `dpopJkt` — the thumbprint of the client's session key — and stamps it on the session.
   This is the draft's `dpop_jkt` idea, and it is the cryptographic join between the
   passkey ceremony and the session key.
3. **Verify at use.** A `verifyDpopProof(request, sessionToken, jkt)` helper in
   `packages/server/src/http.ts`, alongside the cookie and origin helpers already there,
   for the same reason those exist: one correct implementation rather than one per host.
4. **Replay cache.** A `jti` table — hashed key, expiry, single-use, swept by `cleanup()` —
   which is structurally the same row the challenge table already is. It drops into the
   existing store contract without a new idiom.
5. **Optional nonces.** `DPoP-Nonce` and `WWW-Authenticate: DPoP error="use_dpop_nonce"`
   for the pre-generation defence in §8.

Roughly 200–300 lines including the RFC 7638 thumbprint, careful header validation, and the
store method. No OAuth, no JWT issuance, no JWKS, no scopes, no audiences. `Authorization:
Bearer` keeps working; `Authorization: DPoP` is what you reach for when a leaked token
must be useless on its own.

### Why not the draft

The Authorization Challenge Endpoint exists to spare a native app the browser redirect of
the OAuth authorization code flow. This package has no redirect flow to spare anyone — it
is already a direct-to-server ceremony. The draft's output, an authorization code exchanged
for an access token, fills a role the opaque session token already fills.

Implementing it means becoming an OAuth authorization server: codes, a token endpoint, JWT
access tokens, `cnf`/`jkt` claims, a server signing key with rotation and a JWKS endpoint,
scopes, audiences, `authorization_details`. Against a project whose stated pitch is roughly
3,500 reviewable lines, with OIDC and federation as documented non-goals, that is the wrong
trade — and note it would be the wrong trade even though (2)'s architecture is correct.

Track the draft. If it becomes an RFC and someone needs OAuth interop, an adapter that
presents this package's ceremony behind a challenge endpoint is a separate package layered
on top, not a change to the core.

### Revised phasing

Steps 1–3 from (1) §11 are unchanged: versioned migrations, then `kind` end to end, then
challenge-scoped kinds and kind-filtered revocation. That closes issue #11.

Then, as a distinct and independently useful change:

4. **DPoP binding** as above. It benefits browser sessions exactly as much as machine
   sessions — the FIDO white paper's point is about stolen _cookies_ — so it is not
   machine-specific work and should not be gated behind the machine-credential feature.
5. **`@localwebauthn/client`**, which signs the WebAuthn assertion at session start and the
   DPoP proof per request. Both are `crypto.subtle.sign`; the `MachineKeyStore` interface in
   (1) §6 covers the first, and the session key needs no abstraction because it is
   ephemeral and in-memory by design.
6. **Optional:** RFC 9421 plus `Content-Digest` for body integrity, per (3).

## Sources

- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449.html)
- [IANA HTTP Authentication Schemes registry](https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml)
- [draft-ietf-oauth-first-party-apps (Datatracker status)](https://datatracker.ietf.org/doc/draft-ietf-oauth-first-party-apps/)
- [OAuth 2.0 for First-Party Applications (editors' copy)](https://drafts.oauth.net/oauth-first-party-apps/draft-ietf-oauth-first-party-apps.html)
- [FIDO Alliance: DBSC/DPoP as Complementary Technologies to FIDO Authentication](https://fidoalliance.org/white-paper-dbsc-dpop-as-complementary-technologies-to-fido-authentication/)
- [RFC 9729: The Concealed HTTP Authentication Scheme](https://www.rfc-editor.org/rfc/rfc9729.html)
- [RFC 9421: HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
