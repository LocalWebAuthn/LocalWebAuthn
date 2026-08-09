# Security Policy

## The Core Property

**`@localwebauthn/server` never receives or persistently stores credential private keys.** It
stores public credential material and one-way token digests. No flow gives the server a private
key, so no defect in the server package can leak one — not a statement about review quality, but
a consequence of where the keys live: the authenticator generates the key pair and keeps the
private half, and the relying party receives a public key and signatures over challenges it
chose itself. **Human passkeys never reach this project's code at all**; the browser performs
the ceremony.

Three properties must not be conflated, and this document keeps them apart:

| Property                | Claim                                                                                                                                                   |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Server persistence      | **No private key, ever.** Public keys and digests only.                                                                                                 |
| Transient possession    | Human passkeys: none. **Optional components: yes** — `@localwebauthn/client` imports a script's key to sign with, and the demo mint page generates one. |
| Client keystore at rest | Operator's choice: a `chmod 0600` file, or a platform keystore (TPM, Secure Enclave, agent, KMS) that holds the key non-exportably.                     |

The optional-component row is deliberate and worth stating plainly rather than glossing:
`packages/client/src/keystore.ts` can generate an **extractable** key and export PKCS#8, and
`importKeyStore` accepts private-key bytes — that is what a file-based CLI credential requires.
The WebCrypto specification does not guarantee that key material is erased when application
references are dropped ([Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/)), so this
project does not claim zeroization, shredding, or that "exactly one copy" exists. Deployments
wanting no exportable key material should use a platform-keystore signer, where the process
sends bytes to sign and receives a signature but never holds the key.

Three consequences follow, and they are the reason to prefer this shape:

1. **A complete read of the server's authentication data grants no access.** Public keys,
   SHA-256 digests, and metadata. Nothing replayable, nothing worth attacking offline.
2. **There is no secret whose disclosure is permanent or transferable.** A password verifier
   is valuable forever, attackable offline, and often reused at other sites. A public key is
   worth nothing on the day it leaks and nothing in ten years.
3. **Every remaining risk is bounded and revocable.** The capabilities that do grant access —
   a live session, an unredeemed enrollment link, a script's credential file — are single-
   purpose, time-boxed, and killable with one call.

The user's side of this is small, and worth telling them: create human passkeys through the
platform's own facility (secure element, TPM, hardware key, password manager), and store a
script's credential file the way a secret is stored — `chmod 0600`, beside the script, out of
source control. Do those two things and the only durable private key material is the one file
you chose to keep — subject to the caveat above that a value which has passed through a
clipboard, a download or a backup has copies no library can account for.

## Reporting

Do not open a public issue for a suspected vulnerability. Use one of these private
channels instead:

- [GitHub private vulnerability reporting](https://github.com/LocalWebAuthn/LocalWebAuthn/security/advisories/new)
  (preferred — keeps the report, discussion, and eventual advisory together).
- Email `security@dominionrnd.com` (Perry Kundert).

Include the affected version, deployment assumptions, reproduction steps, and likely impact.
Do not include real enrollment links, session tokens, credential material, or user data.

Expect an acknowledgement within a few business days. Please give us a reasonable window
to ship a fix before public disclosure; we will credit you in the advisory unless you ask
otherwise.

## What Is Stored, And What It Is Worth

Every table the package creates, and what it gives a reader:

| Table                             | Holds                                                           | Worth to a reader                                             |
| --------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------- |
| `localwebauthn_credentials`       | COSE **public** key, counter, label, kind, heritage, timestamps | nothing — you cannot sign with a public key                   |
| `localwebauthn_sessions`          | SHA-256 of the session token, user, credential, timestamps      | nothing — a digest is not a bearer token                      |
| `localwebauthn_enrollment_grants` | SHA-256 of the link token and of the enrollment session         | nothing — the link cannot be reconstructed                    |
| `localwebauthn_challenges`        | SHA-256 of the challenge cookie, and the challenge itself       | the challenge is public by design; it was sent to the browser |
| `localwebauthn_dpop_proofs`       | SHA-256 of spent `jti` values                                   | nothing — a replay ledger                                     |
| `localwebauthn_dpop_nonces`       | the current nonce, in the clear                                 | nothing — the server hands it to any caller that asks         |

Enrollment tokens, enrollment session tokens, challenge tokens and application session tokens
each contain 256 bits of random material, and official adapters store **only** SHA-256 digests
of them. A DPoP `jti` is chosen by the client — `@localwebauthn/client` uses 128 random bits —
and the server likewise stores only its digest, in a ledger whose whole purpose is to refuse a
second use. Exactly two stored values are plaintext, and both are
non-secrets by construction: the WebAuthn challenge, which was published to the browser
moments earlier, and the DPoP nonce, whose only property is being unguessable _in advance_.

Enrollment secrets travel in URL **fragments**, so browsers do not put them in requests or
referrers before the browser client explicitly exchanges them.

Passkey public keys, counters, transports, backup state, labels, kinds, heritage and
timestamps are not secrets, but they are authentication data and user metadata: apply normal
database access controls.

Private keys come to rest in two places, neither of which is server state:

- **A person's passkey** — held by a WebAuthn authenticator. Hardware protection, local-only
  storage and backup eligibility are properties of _that_ authenticator and of your policy, not
  universal guarantees: WebAuthn permits hardware, software, platform, roaming and synced
  authenticators, and a backup-eligible credential may be synchronized or recovered by its
  provider ([WebAuthn L3](https://www.w3.org/TR/webauthn-3/),
  [Apple Platform Security](https://support.apple.com/en-euro/guide/security/sec1c89c6f3b/web)).
  What is universal: the provider is not an identity provider for your application, it never
  hands LocalWebAuthn a key, and `@localwebauthn/browser` touches no key material at all. If
  your policy depends on attestation, backup eligibility or backup state, document exactly what
  you check and what you trust that signal to mean.
- **A script's Passkey** — the file the operator provisioned, or a reference to a platform
  keystore. `@localwebauthn/client` reads it and holds it in process memory to sign with; it
  writes it nowhere. The mint page displays it once — which describes the page, not the world:
  a value that passed through a clipboard, a Downloads folder, terminal scrollback or a backup
  has copies this project cannot see or erase. See [docs/API-AUTH.org](docs/API-AUTH.org) for
  custody options, including a TPM or Secure Enclave signer so no file holds a key.

## What A Disclosure Costs

| Disclosure                               | What the attacker gains                                                                                                                                           |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| the whole server database, read-only     | **nothing usable** — public keys, digests, metadata                                                                                                               |
| a database backup from any point in time | nothing usable, then or ever — public keys do not become interesting with age                                                                                     |
| a live session cookie                    | that one session, until it expires or `revokeSession` / `revokeUserSessions` ends it                                                                              |
| a live machine session token             | nothing on its own — a request also needs a DPoP proof signed by the credential's key, and a token without the key cannot even keep the session alive (see below) |
| an unredeemed enrollment link            | one passkey on that account. A real bearer capability — hence single-use, minutes long, and delivered on a channel the host chooses                               |
| a script's credential file               | that one credential, until `revokeCredential`; the heritage columns record what it created                                                                        |
| **write** access to the database         | everything — an attacker can insert their own public key. Read disclosure and write compromise are different events, and only the first is bounded                |

**The database rows above are what is durable and non-authenticating.** Raw bearer tokens are
a different matter: LocalWebAuthn does not intentionally log or persist them, but they are
generated and received by the server process and returned through HTTP, so a crash dump, a
verbose trace, or an APM span captured **during a request** can contain a session token, an
enrollment token, a live challenge, or an `Authorization`/`Cookie` header. That is a
live-process and observability concern, distinct from database-at-rest disclosure, and it is
the host's to manage: redact `Authorization`, `Cookie`, `Set-Cookie`, enrollment values and
URL fragments from logs and traces, and disable or encrypt production crash dumps.

The machine-session-token guarantee holds **when the host resolves machine requests through
`authenticateMachineRequest`** (or an equivalent that verifies the DPoP proof before touching
the session). That one call derives the session from the token, requires a proof, and refreshes
the session's activity only after the proof succeeds — so a token-only thief can neither make a
request nor keep the session alive. Resolving the session first with the default activity touch,
and verifying the proof afterward, reopens the idle-refresh side channel; do not.

Two things this does **not** claim. A compromised server can alter code and hijack future
sessions; no storage property helps there. And recovery is where a passkey deployment can end
up worse than a password one — build "email me a link" recovery and you have rebuilt the
password reset flow and put the mailbox back in front of the passkey. Design it deliberately;
[README-DETAIL.org](README-DETAIL.org) has a section on it.

## Supported Versions

Security fixes are applied to the most recent minor release of the current major version.
LocalWebAuthn follows SemVer for the host-facing service API. Official storage adapters
and the database schema stay compatible across minor releases. Custom
`LocalWebAuthnStore` implementations may need updates when a minor release tightens the
store contract for correctness (see [docs/MIGRATING.md](docs/MIGRATING.md)).

A stable interface is not a production track record. The project is young and has a small
user base. It is also small on purpose, so that a reviewer can read the whole authentication
path rather than trust it:

|                                                                    | Lines  | Who has to read it                       |
| ------------------------------------------------------------------ | ------ | ---------------------------------------- |
| `@localwebauthn/server` — service, all three adapters, schema, SQL | ~6,030 | every deployment                         |
| `@localwebauthn/browser`                                           | ~180   | deployments with a browser front end     |
| `@localwebauthn/client` — software authenticator, DPoP             | ~1,000 | only deployments issuing API credentials |

Machine credentials took the server package from roughly 3,970 lines to 6,030. The default
path barely moved — a deployment that declares no `credentialKinds`, configures no
`dpopNonce` and never sets a `credentialKind` behaves as it did — but the _audit_ surface
grew with it, and that cost is real. If you are reviewing and do not issue API credentials,
`packages/server/src/dpop.ts` and the `credentialKinds` handling are the parts you can skip.

Every SQL statement the package executes is collected in one module,
`packages/server/src/queries.ts`, to make that review tractable. Please do read it, and
report anything that looks wrong.

Being young is a real risk, and it is a different _kind_ of risk than a password system's. A
bug here can grant access — a mishandled challenge, a leaked enrollment link, a session
mistake — but it cannot create a persistent, transferable secret, because none exists. A
password system's central liability is present by design on the day it ships, no matter how
well reviewed: it receives the user's reusable secret on every login and stores a verifier
worth attacking forever.

## Security Boundary

LocalWebAuthn relies on:

- `@simplewebauthn/server` for WebAuthn parsing and cryptographic verification.
- A cryptographically secure Web Crypto implementation.
- Exact RP IDs and allowlisted origins supplied by the host.
- Stable, random 32-byte WebAuthn user handles supplied by the host.
- Atomic behavior from an official storage adapter or a conforming custom adapter.
- HTTPS outside local development.

The host application must:

- Put enrollment, challenge, and session tokens in `Secure`, `HttpOnly`, `SameSite=Strict`
  cookies using `__Host-` names under HTTPS — `authCookieNames` and `cookieAttributes`
  on `@localwebauthn/server` implement exactly this; do not re-derive the flags.
- Reject state-changing requests whose exact `Origin` is not allowlisted
  (`isExactOrigin` implements the comparison).
- Apply endpoint and identity-aware rate limits.
- Deliver enrollment links through an approved confidential channel.
- Suspend users by returning `active: false` from `getUser` — every ceremony and
  session resolution refuses an inactive user — and use `revokeUserSessions` (sessions
  only) or `revokeUserAuthentication` (credentials too) to revoke their stored state.
- Require a _fresh_ passkey assertion for recovery and sensitive credential changes.
- Refuse non-interactive credential kinds at its cookie-session middleware if it issues
  machine credentials (`interactiveKind`), which is the only thing that closes the
  grant-path self-replication chain.
- Persist and monitor structured authentication audit events.

## Storage Adapter Guarantees

The SQLite and PostgreSQL adapters wrap every multi-statement operation in a real
transaction, so a registration or authentication either commits completely or not at all.
Prefer one of them when you have the choice.

Schedule `cleanup()` periodically on any adapter — every few minutes is ample. It reclaims
storage from expired enrollment grants, finished challenges, and dead sessions.
Credentials are not cleaned up: they are durable authenticators, revoked only through
`revokeCredential` / `revokeUserAuthentication`.

The SQLite adapter enables `PRAGMA foreign_keys = ON` for the connection it is given
(in both `migrateSqlite` and the store constructor). Keep using that same connection so
schema foreign keys stay enforced.

## D1 Batch Transactions

The Cloudflare D1 adapter runs each multi-statement operation as one `batch()`, which D1
executes as a single transaction: "If a statement in the sequence fails, then an error is
returned for that specific statement, and it aborts or rolls back the entire sequence"
([Cloudflare D1 Worker API](https://developers.cloudflare.com/d1/worker-api/d1-database/)).
So `completeRegistration` on D1 commits the credential, the grant completion and the initial
session together, or not at all — the same all-or-nothing outcome the SQLite and PostgreSQL
adapters get from an explicit transaction. The row-count guard the D1 adapter carries
(the `localwebauthn_transaction_guard` CHECK) is a compare-and-swap check, not a substitute
for atomicity: a guard that trips fails its statement and rolls the whole batch back.

(Earlier releases of this document described D1 batches as non-atomic and warned of an
"orphan credential without a session." That was based on outdated behaviour; current D1
rolls the batch back, so that outcome does not occur.)

## Enrollment Invariant

Every registration challenge is bound to an immutable enrollment grant ID and the exchanged
enrollment session. Replacing an enrollment grant revokes the prior grant and emits an
`enrollment.revoked` event.

Credential creation, exact-grant completion, and session creation are committed as one
transaction by all three adapters — SQLite and PostgreSQL through explicit transactions, D1
through a single [batch transaction](#d1-batch-transactions). A registration that loses its
authorization mid-flight rolls back completely on every adapter, so there is no partial or
orphaned state to reconcile.

## Compromise Revocation Is Bounded, Not Instantaneous

`revokeCredentialTree` and the kind-scoped `revokeUserAuthentication` are the remediation
primitives for a compromised credential: they revoke a credential and everything descended
from it. They re-enumerate to a fixed point, so a credential registered **concurrently** with
the revoke — by a live session racing it — is caught on re-read rather than surviving a stale
snapshot, and a batch of registrations pre-staged against a credential all fail once that
credential is revoked (the conditional insert requires the authorizer's `revoked_at IS NULL`).

The bound is honest: an attacker who wins the registration race in _every_ pass is not fully
fenced by re-enumeration alone. A complete guarantee needs a registration epoch that a single
revoke invalidates (tracked in [docs/REVIEW-20260809.md](docs/REVIEW-20260809.md) §3). Until
that lands, a host performing incident response should also stop accepting registrations for
the affected user — the surest fence is to remove the authority to register at all while
remediating.

## Non-Goals

LocalWebAuthn does not provide authorization, user identity verification, email delivery,
account recovery policy, OAuth, OIDC, or password fallback.

It does authenticate non-browser clients: a credential carries a host-defined `kind`, and a
software client can complete the ceremony without a browser or a human. Such a credential's
`userVerified`, `origin`, `deviceType` and counter are claims a program makes about itself
and must never be read as evidence of a person — `kind` is the only fact about a
credential's class that a hostile key holder cannot forge. See
[docs/API-AUTH.org](docs/API-AUTH.org).
