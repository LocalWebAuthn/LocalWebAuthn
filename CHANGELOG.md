# Changelog

## 1.0.0 - 2026-07-30

### Added

- **Orphaned-credential cleanup**: both `cleanup()` implementations now remove
  credentials that have no session rows and were created more than one hour ago.
  This recovers storage from rare D1 mid-batch guard failures.
- **`enrollment.revoked` audit event**: emitted when `issueEnrollment` implicitly
  revokes a prior pending grant for the same user.
- **`logger` configuration option**: defaults to `console`; receives warnings
  when the `onEvent` callback throws. Previously these errors were silently
  swallowed.
- **`rpId` format validation**: configuration rejects non-hostname RP IDs at
  construction time rather than failing cryptically during ceremony generation.
- **`createChallenge` duplicate detection**: returns `boolean`; the service
  throws a clear `409` on the astronomically-unlikely collision.
- **Comprehensive TSDoc** on `LocalWebAuthnOptions`, `LocalWebAuthnStore`,
  `AuthUser`, `UserProvider`, `Credential`, `SessionIdentity`, and the
  `LocalWebAuthn` class public methods.
- **Service-level test for `revokeUserAuthentication`**.
- **Store conformance test for orphaned-credential cleanup** (SQLite and D1).

### Changed

- **BREAKING**: `replaceEnrollmentGrant` returns `Promise<string[]>` (IDs of
  revoked grants) instead of `Promise<void>`.
- **BREAKING**: `createChallenge` returns `Promise<boolean>` instead of
  `Promise<void>`.
- **BREAKING**: `CleanupResult` gains an `orphanedCredentials: number` field.
- **D1 `completeRegistration`**: restructured with labeled parameters and
  path documentation for auditability.
- **Demo error detection**: uses explicit `clientByEmail()` pre-check instead
  of parsing SQLite constraint-error strings.

### Security

- Documented D1 batch non-atomicity in `SECURITY.md`.
- Audit trail now includes implicitly revoked enrollment grants.

## 0.1.1 - 2026-07-30

- Export the WebAuthn ceremony response types needed by HTTP adapters.
- Add a complete SQLite lifecycle demo with administrator bootstrap, user enrollment,
  additional passkeys, revocation, and Playwright virtual-passkey coverage.
- Document the passkey-first rationale, security boundary, integration path, and
  reproducible demo media.

## 0.1.0 - 2026-07-30

- Publish the initial `@localwebauthn/server` and `@localwebauthn/browser` packages.
- Provide conforming SQLite and Cloudflare D1 stores.
