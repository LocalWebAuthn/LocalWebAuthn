# Security Policy

## The Core Property

**LocalWebAuthn never possesses private key material.** There is no point in any flow where a
private key passes through code in this repository, so no defect in this repository can leak
one. That is not a statement about review quality — it is a consequence of where the keys
live. The authenticator generates the key pair and keeps the private half; the relying party
receives a public key and signatures over challenges it chose itself.

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
source control. Do those two things and no private key exists anywhere else.

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

Private keys live in exactly two places, neither of which is this package:

- **A person's passkey** — the platform keystore. Device-bound keys are non-exportable in
  hardware; synced platform passkeys are protected by the provider with the user's account and
  device unlock. That provider is not an identity provider for your application, because it
  never hands LocalWebAuthn a key. `@localwebauthn/browser` touches no key material at all.
- **A script's Passkey** — the one file the operator provisioned, or a reference to a platform
  keystore. `@localwebauthn/client` reads it and holds it in process memory; it never writes
  it anywhere. The mint page displays it once, and the server keeps only the public half, so
  there is one copy in one place. See [docs/API-AUTH.org](docs/API-AUTH.org) for the custody
  options, including keeping the key in a TPM or Secure Enclave so the file holds no key.

## What A Disclosure Costs

| Disclosure                               | What the attacker gains                                                                                                                            |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| the whole server database, read-only     | **nothing usable** — public keys, digests, metadata                                                                                                |
| a database backup from any point in time | nothing usable, then or ever — public keys do not become interesting with age                                                                      |
| server logs, traces, crash dumps         | nothing usable — no reusable secret ever crosses the process                                                                                       |
| a live session cookie                    | that one session, until it expires or `revokeSession` / `revokeUserSessions` ends it                                                               |
| a live machine session token             | nothing on its own — each request also needs a DPoP proof signed by the credential's key                                                           |
| an unredeemed enrollment link            | one passkey on that account. A real bearer capability — hence single-use, minutes long, and delivered on a channel the host chooses                |
| a script's credential file               | that one credential, until `revokeCredential`; the heritage columns record what it created                                                         |
| **write** access to the database         | everything — an attacker can insert their own public key. Read disclosure and write compromise are different events, and only the first is bounded |

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

## D1 Batch Non-Atomicity

The Cloudflare D1 adapter uses `batch()` to execute multiple statements. Unlike the
SQLite adapter's explicit transactions, D1 batches are **not atomic** — each statement
commits independently. A rare concurrent-failure scenario in `completeRegistration` can
leave a credential row without its initial session when a later statement in the batch
fails after the credential INSERT committed.

That row remains a normal passkey: the next successful authentication creates a session.
There is no separate “orphan credential” cleanup path.

## Enrollment Invariant

Every registration challenge is bound to an immutable enrollment grant ID and the exchanged
enrollment session. Replacing an enrollment grant revokes the prior grant and emits an
`enrollment.revoked` event.

Credential creation, exact-grant completion, and session creation are committed as one
transaction by the SQLite and PostgreSQL adapters. The D1 adapter cannot open a
transaction and instead guards each step on the preceding statement's row count; see
[D1 Batch Non-Atomicity](#d1-batch-non-atomicity) above for what that does and does not
guarantee. On SQLite and PostgreSQL, a registration that loses its authorization
mid-flight rolls back completely. On D1, a mid-batch failure after the credential INSERT
can leave a usable credential without an initial session — the user signs in again rather
than being auto-logged-in. No cleanup step is required to reconcile that state.

## Non-Goals

LocalWebAuthn does not provide authorization, user identity verification, email delivery,
account recovery policy, OAuth, OIDC, or password fallback.

It does authenticate non-browser clients: a credential carries a host-defined `kind`, and a
software client can complete the ceremony without a browser or a human. Such a credential's
`userVerified`, `origin`, `deviceType` and counter are claims a program makes about itself
and must never be read as evidence of a person — `kind` is the only fact about a
credential's class that a hostile key holder cannot forge. See
[docs/API-AUTH.org](docs/API-AUTH.org).
