# Security Policy

## Supported Versions

Security fixes are applied to the most recent minor release of the current major version.
LocalWebAuthn follows SemVer for the host-facing service API. Official storage adapters
and the database schema stay compatible across minor releases. Custom
`LocalWebAuthnStore` implementations may need updates when a minor release tightens the
store contract for correctness (see [docs/MIGRATING.md](docs/MIGRATING.md)).

A `1.x` version means the interface is stable, not that the code has years of production
exposure. The project is young and has a small user base. It is also small on purpose, so
that a reviewer can read the whole authentication path rather than trust it:

|                                                                    | Lines  | Who has to read it                       |
| ------------------------------------------------------------------ | ------ | ---------------------------------------- |
| `@localwebauthn/server` — service, all three adapters, schema, SQL | ~5,960 | every deployment                         |
| `@localwebauthn/browser`                                           | ~180   | deployments with a browser front end     |
| `@localwebauthn/client` — software authenticator, DPoP             | ~1,000 | only deployments issuing API credentials |

Machine credentials took the server package from roughly 3,970 lines to 5,960. The default
path barely moved — a deployment that declares no `credentialKinds`, configures no
`dpopNonce` and never sets a `credentialKind` behaves as it did — but the _audit_ surface
grew with it, and that cost is real. If you are reviewing and do not issue API credentials,
`packages/server/src/dpop.ts` and the `credentialKinds` handling are the parts you can skip.

Every SQL statement the package executes is collected in one module,
`packages/server/src/queries.ts`, to make that review tractable. Please do read it, and
report anything that looks wrong.

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
- Require a fresh passkey assertion for recovery and sensitive credential changes.
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

## Stored Secrets

Enrollment tokens, enrollment sessions, challenge tokens, and application sessions contain
256 bits of random material. Official adapters store only SHA-256 digests. Enrollment secrets
are placed in URL fragments so browsers do not transmit them in HTTP requests or referrers
before the browser client explicitly exchanges them.

Passkey public keys, counters, transports, backup state, labels, and timestamps are not
secrets, but they are authentication data and require normal database access controls.

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
