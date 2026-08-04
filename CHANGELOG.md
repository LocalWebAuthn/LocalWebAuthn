# Changelog

## 1.1.0 - 2026-08-04

No breaking changes. Custom `LocalWebAuthnStore` implementations written against
1.0.0 continue to work; the store contract is unchanged.

### Added

- **PostgreSQL adapter**: `PostgresLocalWebAuthnStore` and `migratePostgres` from
  `@localwebauthn/server/postgres`, plus `LOCALWEBAUTHN_POSTGRES_SCHEMA_SQL` from
  `@localwebauthn/server/schema`. Like SQLite and unlike D1, it uses real
  transactions. `pg` is an optional peer dependency.
- The store conformance suite now runs against all three adapters. PostgreSQL
  requires a real server (`pg-start` in the nix devShell, or CI's service
  container) and skips when none is reachable — except in CI, where
  `LOCALWEBAUTHN_REQUIRE_POSTGRES=1` turns an unreachable server into a failure
  so the suite can never silently skip.
- Conformance coverage for duplicate challenge IDs, which 1.0.0 implemented but
  never tested.
- `flake.nix` provides PostgreSQL 17 with `pg-start` / `pg-stop` helpers.
- CI runs the check job on Node 22 and 24; 22 is the minimum the packages declare.

### Changed

- All SQL now lives in one internal module, so each statement has a single
  definition to audit instead of one per adapter. The SQLite and D1 adapters
  shrank by roughly 590 lines between them with no behavior change.
- SQLite `exchangeEnrollment` and `consumeChallenge` are now single atomic
  `UPDATE ... RETURNING` statements rather than a `SELECT` followed by an
  `UPDATE` inside a transaction. Same guarantee, fewer moving parts.
- The D1 credential insert was one statement with 19 positional parameters that
  branched on `? IS NOT NULL`. It is now two single-purpose statements, chosen
  by the caller that already knows which authorization path applies.
- Row mappers coerce numeric columns and booleans, since node-postgres returns
  `BIGINT` as a string and `BOOLEAN` as a real boolean. Values that cannot
  round-trip as safe integers now raise rather than silently truncating.

### Documentation

- A "Coming From Password Authentication" section maps each password concept to
  its replacement, explains why sign-in takes two requests instead of one, and
  notes that no username is submitted.
- The six HTTP endpoints the browser client calls are documented in a table with
  the cookies each one sets, alongside a complete Hono adapter. Previously these
  were discoverable only by reading the browser package source.

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
