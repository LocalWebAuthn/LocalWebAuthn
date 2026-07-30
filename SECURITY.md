# Security Policy

## Supported Versions

Security fixes are applied to the most recent minor release of the current major version.
LocalWebAuthn follows SemVer: the service API, store interface, and database schema change
only in a new major version.

`1.0.0` means the interface is stable, not that the code has years of production exposure.
The project is young and has a small user base. It is also small on purpose — under 3,000
lines of TypeScript across the service, both storage adapters, and the browser client —
so that a reviewer can read the whole authentication path rather than trust it. Please do
read it, and report anything that looks wrong.

## Reporting

Do not open a public issue for a suspected vulnerability. Report it privately to the
repository owner.

Include the affected version, deployment assumptions, reproduction steps, and likely impact.
Do not include real enrollment links, session tokens, credential material, or user data.

Maintainer note: GitHub private vulnerability reporting is not yet enabled on this
repository. Enabling it under Settings → Code security gives reporters an authenticated
private channel and should be done before the project attracts wider use.

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
  cookies using `__Host-` names under HTTPS.
- Reject state-changing requests whose exact `Origin` is not allowlisted.
- Apply endpoint and identity-aware rate limits.
- Deliver enrollment links through an approved confidential channel.
- Revoke LocalWebAuthn state whenever a user is deactivated.
- Require a fresh passkey assertion for recovery and sensitive credential changes.
- Persist and monitor structured authentication audit events.

## D1 Batch Non-Atomicity

The Cloudflare D1 adapter uses `batch()` to execute multiple statements. Unlike the
SQLite adapter's explicit transactions, D1 batches are **not atomic** — each statement
commits independently. A rare concurrent-failure scenario in `completeRegistration` can
leave an orphaned credential row: the credential INSERT succeeds but the session INSERT
is never reached because the batch guard detected a mid-batch inconsistency.

Orphaned credentials are harmless (they cannot be used to authenticate without a session
row) but consume storage. The `cleanup()` method removes credentials that have no session
rows and were created more than one hour ago.

Applications deployed on D1 should schedule periodic `cleanup()` calls.

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
transaction by the SQLite adapter. The D1 adapter cannot open a transaction and instead
guards each step on the preceding statement's row count; see
[D1 Batch Non-Atomicity](#d1-batch-non-atomicity) above for what that does and does not
guarantee. In both adapters, a registration that loses its authorization mid-flight
produces no usable credential.

## Non-Goals

LocalWebAuthn does not provide authorization, user identity verification, email delivery,
account recovery policy, API-token authentication, OAuth, OIDC, or password fallback.
