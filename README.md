# LocalWebAuthn

LocalWebAuthn provides a self-hosted, invitation-first, passkey-only authentication
lifecycle for TypeScript applications. It delegates WebAuthn ceremony generation and
verification to SimpleWebAuthn and keeps application users and authorization policy under
the application's control.

The repository contains two packages:

- `@localwebauthn/server`: framework-neutral enrollment, registration, authentication,
  credential, and session lifecycle with SQLite and Cloudflare D1 adapters.
- `@localwebauthn/browser`: a small browser client for the default HTTP endpoint protocol.

LocalWebAuthn is pre-release software. Treat `0.x` APIs and schemas as unstable and review the
threat model before deploying it.

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

## Repository Commands

```console
nix develop
make check
```

`make check` runs TypeScript, lint, formatting, unit and adapter conformance tests, package
builds, `publint`, and `arethetypeswrong`.

## Package Development

The npm workspaces can be consumed directly from a sibling or submodule checkout:

```json
{
  "dependencies": {
    "@localwebauthn/browser": "file:vendor/localwebauthn/packages/browser",
    "@localwebauthn/server": "file:vendor/localwebauthn/packages/server"
  }
}
```

Run `npm install` in the LocalWebAuthn checkout before running its tests. Generated `dist`
artifacts are committed while Pulse consumes a pinned submodule, so a fresh Pulse checkout
does not require LocalWebAuthn's development dependencies. npm releases rebuild those
artifacts from source in the protected release workflow.

## Release

The package manifests are prepared for public publication under the `@localwebauthn` npm
organization. Before the first release:

1. Create the `localwebauthn` npm organization and public source repository.
2. Verify the repository URLs in both package manifests.
3. Publish the first public versions with publishing 2FA.
4. Configure npm Trusted Publishing for `.github/workflows/publish.yml`.
5. Require a protected GitHub release environment and review the packed artifacts.

The release workflow uses npm OIDC trusted publishing and does not require a long-lived npm
write token. See [docs/RELEASING.md](docs/RELEASING.md) for the bootstrap and regular release
checklists.
