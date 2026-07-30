# Security Policy

## Supported Versions

LocalWebAuthn is experimental while its version is below `1.0.0`. Security fixes are applied
to the most recent minor release only.

## Reporting

Do not open a public issue for a suspected vulnerability. Before publication, report
vulnerabilities privately to the repository owner. A dedicated security contact and GitHub
private vulnerability reporting must be configured before the first npm release.

Include the affected version, deployment assumptions, reproduction steps, and likely impact.
Do not include real enrollment links, session tokens, credential material, or user data.

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

## Stored Secrets

Enrollment tokens, enrollment sessions, challenge tokens, and application sessions contain
256 bits of random material. Official adapters store only SHA-256 digests. Enrollment secrets
are placed in URL fragments so browsers do not transmit them in HTTP requests or referrers
before the browser client explicitly exchanges them.

Passkey public keys, counters, transports, backup state, labels, and timestamps are not
secrets, but they are authentication data and require normal database access controls.

## Enrollment Invariant

Every registration challenge is bound to an immutable enrollment grant ID and the exchanged
enrollment session. Replacing an enrollment grant revokes the prior grant. Credential
creation, exact-grant completion, and session creation commit atomically.

## Non-Goals

LocalWebAuthn does not provide authorization, user identity verification, email delivery,
account recovery policy, API-token authentication, OAuth, OIDC, or password fallback.
