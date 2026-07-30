# Why LocalWebAuthn

## Problem

WebAuthn is a ceremony protocol, not a complete local authentication lifecycle.
SimpleWebAuthn provides the correct primitives for generating and verifying registration
and authentication ceremonies. An application adopting those primitives must still decide:

- How an approved person receives a single-use enrollment capability.
- How enrollment survives HTTP requests without exposing durable secrets.
- How challenges are stored, expired, and atomically consumed.
- How credentials, transports, backup state, and signature counters are updated.
- How an authenticated client adds a second passkey without a recovery loophole.
- How opaque sessions expire, idle, touch, revoke, and bind to credentials.
- How grant replacement invalidates an earlier in-flight ceremony.
- How the same invariants are enforced by SQLite and Cloudflare D1.

These decisions are security-critical but largely independent of an application's business
domain. Reimplementing them in every local passkey application creates boilerplate, subtle
transaction bugs, and review work.

## Why Not Only SimpleWebAuthn

LocalWebAuthn uses SimpleWebAuthn as its ceremony provider. It does not replace or fork that
cryptographic implementation.

SimpleWebAuthn intentionally leaves persistence and application lifecycle to its consumers.
LocalWebAuthn formalizes one opinionated lifecycle around it:

1. An application creates a user with a stable random WebAuthn user handle.
2. An administrator or bootstrap operator issues a 256-bit one-time enrollment token.
3. The package stores only the token digest and exchanges it once for a short session.
4. A registration challenge is bound to that exact grant generation.
5. Successful registration atomically stores the credential, completes the grant, and
   creates an opaque authenticated session.
6. Later authentication atomically checks and advances the credential counter while
   creating a new session.
7. An authenticated session can authorize another credential for the same user.

The ceremony remains SimpleWebAuthn. The reusable state machine and storage invariants are
LocalWebAuthn.

## Why Not Require An External Identity Provider

OIDC providers and hosted authentication services are often the right choice. They also add
an external administrative plane, dependency, outage boundary, and user-data repository.

LocalWebAuthn targets applications that deliberately want:

- Passkey-only human authentication.
- A local user directory controlled by the application.
- No password database or password recovery flow.
- No required hosted identity or email service.
- SQLite for a single-node deployment or D1 for a Cloudflare deployment.

It is not an identity-proofing service. The host still decides who a user is, who may approve
an enrollment, and how the bearer enrollment link reaches that person.

## Boilerplate Reduction

A host integration supplies:

```ts
const auth = new LocalWebAuthn({
  rpName: 'Example',
  rpId: 'app.example.com',
  expectedOrigins: 'https://app.example.com',
  store: new SqliteLocalWebAuthnStore(database),
  users: {
    async getUser(userId) {
      return applicationUsers.getForAuthentication(userId);
    },
  },
});
```

The package then owns:

- Schema creation for grants, challenges, credentials, sessions, and migrations.
- Hashed enrollment and session tokens.
- Exact grant-generation binding for registration.
- Atomic challenge consumption and replay rejection.
- Credential counter compare-and-update.
- Idle and absolute session expiration.
- Credential and user-wide revocation.
- The same storage contract for SQLite and D1.

The host route adapter remains intentionally small and framework-specific: read JSON, read or
write HTTP-only cookies, enforce the exact origin, call the service, and map errors. The demo
shows this complete boundary without hiding it behind a hosted service or a large framework.

## Local Database Ownership

The SQLite and D1 adapters are official parts of `@localwebauthn/server`. Applications run
the adapter migration and do not issue SQL against `localwebauthn_*` tables.

The host owns only its user table. In the demo that table contains:

- Application user ID.
- Email and display name.
- Application role and activation state.
- Stable random 32-byte WebAuthn user handle.

Credential public keys are local authentication data, but they are managed through the
package's store interface. Private keys and biometric data never reach the server.

## Deliberate Non-Goals

LocalWebAuthn does not provide:

- Email delivery or mailbox verification.
- Social login, enterprise federation, or OIDC.
- Password fallback.
- Recovery identity proofing.
- Roles, groups, tenants, or business authorization.
- Cookie or CSRF policy for a particular HTTP framework.
- Automated rate limiting.
- Device attestation policy.
- Machine-to-machine authentication.

These policies vary materially between applications. Keeping them outside the package makes
the security boundary smaller and easier to review.

## Security Posture

Enrollment URLs are bearer secrets. Whoever can use an unexpired URL first can register a
passkey for that user. Production systems must approve, deliver, redact, expire, and rate
limit those links appropriately.

LocalWebAuthn reduces the implementation surface but does not make deployment security
automatic. Exact HTTPS origins, secure cookies, origin enforcement, database protection,
auditing, recovery procedures, and dependency updates remain host responsibilities. Review
[SECURITY.md](../SECURITY.md) before deployment.
