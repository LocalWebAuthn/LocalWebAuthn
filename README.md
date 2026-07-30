# LocalWebAuthn

LocalWebAuthn is a self-hosted, invitation-first, passkey-only authentication lifecycle
for TypeScript applications. It keeps users and authorization in the host application,
delegates WebAuthn cryptography to SimpleWebAuthn, and supplies the durable enrollment,
credential, challenge, and session behavior between those two layers.

The project exists for applications that want local passkeys without operating passwords
or depending on an external identity provider. See [Why LocalWebAuthn](docs/RATIONALE.md)
for the design rationale and tradeoffs.

LocalWebAuthn is `0.x` software. Treat its APIs and schemas as unstable and review
[SECURITY.md](SECURITY.md) before deployment.

## Packages

- `@localwebauthn/server` provides the framework-neutral lifecycle and conforming SQLite
  and Cloudflare D1 stores.
- `@localwebauthn/browser` performs enrollment, registration, authentication, and logout
  through a small default HTTP protocol.

```console
npm install @localwebauthn/server @localwebauthn/browser
```

## What It Removes

SimpleWebAuthn correctly implements WebAuthn ceremonies. A complete local authentication
system still needs to design and test one-time invitations, challenge consumption,
credential counters, additional-passkey authorization, opaque sessions, revocation, and
database concurrency.

LocalWebAuthn supplies those lifecycle rules and their persistence:

| Concern                                            | Host using LocalWebAuthn |
| -------------------------------------------------- | ------------------------ |
| Application users and authorization                | Owns                     |
| Link approval and delivery                         | Owns                     |
| HTTP cookies, exact-origin checks, and rate limits | Owns                     |
| Enrollment grants and replay protection            | Package                  |
| Registration and authentication challenges         | Package                  |
| Credential metadata and signature counters         | Package                  |
| Session expiry, touch, logout, and revocation      | Package                  |
| SQLite and D1 authentication schemas               | Package                  |

The host provides one stable user lookup and selects a storage adapter. It never needs to
write LocalWebAuthn tables directly.

## Run The Demo

The example is a complete, local lifecycle application. It prints the initial administrator
enrollment URL, lets that administrator create clients and enrollment links, and lets every
authenticated client register additional passkeys.

```console
nix develop
make demo-reset
make demo
```

Open the enrollment URL printed by the server. The demo listens only on
`http://localhost:4173` and stores its disposable SQLite database under
`examples/demo/.data/`.

The UI includes:

- Initial administrator passkey bootstrap.
- Passkey-only sign-in and logout.
- Administrator-created client records.
- One-time enrollment URLs for new or existing clients.
- Client enrollment on another browser or device.
- Additional passkeys authorized by an existing authenticated session.
- Credential and whole-client authentication revocation.

See [examples/demo/README.md](examples/demo/README.md) for the code map, security boundary,
and automated lifecycle test.

## Scope

LocalWebAuthn owns:

- One-time enrollment grants and short-lived enrollment sessions.
- WebAuthn registration and authentication ceremonies.
- Passkey credentials, counters, labels, and revocation.
- Opaque sessions with idle and absolute expiry.
- Atomic replay protection and cleanup operations.

The host application owns:

- User creation, names, activation, and stable user IDs.
- Delivery and approval of enrollment links.
- Identity proofing, email, recovery, and help-desk policy.
- Roles, groups, tenants, and authorization.
- HTTP cookies, CSRF/origin enforcement, rate limiting, and audit persistence.

This boundary is intentional. Authentication lifecycle is reusable; identity proofing and
business authorization are application policy.

## Repository Commands

```console
nix develop
make check
make demo-test
```

`make check` runs TypeScript, lint, formatting, unit and adapter conformance tests, package
builds, `publint`, and `arethetypeswrong`. `make demo-test` runs the complete lifecycle with
Playwright virtual passkeys.

## Package Development

This repository is an npm workspace. The demo consumes the local server and browser
workspaces at the same version that is published to npm.

```console
npm ci
npm run build
npm test
```

Generated package `dist` artifacts are committed so Git consumers can resolve the package
exports without installing the repository's development dependencies. Releases rebuild and
validate those artifacts.

## Release

Both public packages are versioned together. The initial `0.1.0` package records have been
created under the `@localwebauthn` npm organization. Subsequent GitHub Releases use npm OIDC
Trusted Publishing and require no long-lived npm write token.

See [docs/RELEASING.md](docs/RELEASING.md) for the release checklist.
