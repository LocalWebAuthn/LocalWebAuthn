# Changelog

## Unreleased

### Added

- **`revokePendingEnrollments(userId)`** on `LocalWebAuthn` and store method
  `revokePendingEnrollmentGrants` — revoke outstanding grants without touching
  credentials. Used when an invite must be abandoned after delivery failure.
- **`inviteAndDeliver`**: if no channel accepts the enrollment message (or
  delivery throws), pending grants are revoked. Outcome fields document
  `grantStatus`, `anyDelivered`, and `revokedGrantIds`. Partial delivery
  (one channel ok) keeps the grant live.

### Documentation

- MIGRATING: custom store method and invite delivery cleanup semantics.

## 2.2.0 - 2026-08-06

Additive release: no changes are required for applications using the official
adapters and the `LocalWebAuthn` service API. Custom `SqliteDatabase` drivers
need one method; see [docs/MIGRATING.md](docs/MIGRATING.md#210--220).

### Added

- **HTTP adapter helpers** on `@localwebauthn/server`: `authCookieNames`,
  `cookieAttributes`, `isExactOrigin`, `parseCookieHeader`, `serializeCookie`,
  and related utilities so host apps share one Secure / `__Host-` / origin
  implementation.
- **Signup phase helpers**: `signupPhase`, `nextSignupStep`,
  `describeSignupPhase`, and `SELF_SERVE_SIGNUP_STEPS` for host-owned enrollment
  sequencing without inventing ad-hoc pending flags.
- **Hono starter** at `examples/starter-hono` (six routes + invite + session
  probe). Lifecycle demo uses the same cookie/origin helpers.
- **Channel delivery examples** with internal-only sending — no deployment
  exposes a send API. `examples/channels` (shared fixed templates, destination
  validation, fetch-based Twilio/Resend senders, `inviteAndDeliver`),
  `examples/channels-node` (traditional server: SMTP application password +
  Twilio), and `examples/channels-cf` (fully Cloudflare: Workers + D1 issuing
  real grants, Resend + Twilio, bearer-guarded invite route, Miniflare tests of
  the bundled source). No live credentials required in CI.
- **Self-serve signup proofing** (`channels-core` `signup.ts`): a shared state
  machine issuing one capability-free proof link per channel; the enrollment
  grant exists only after the last required proof, then any channel's link
  claims the same single-use enrollment (claim-on-reopen). Channels are
  open-ended (link-borne or host-attested). Recovery of existing accounts adds
  the state-of-the-art controls: any valid channel OTP can veto ("this wasn't
  me"), completion opens a waiting period during which the account is
  untouched, and any successful passkey sign-in cancels live recoveries via
  the `credential.authenticated` event. The lifecycle demo runs the whole flow
  with simulated delivery, covered by API tests and a Playwright spec
  including the sign-in veto.
- **COMPARISON.md**: JS developer friction section and starter-kit roadmap.

### Fixed

- Store adapters no longer swallow unexpected storage errors in
  `completeRegistration` / `completeAuthentication`. Real faults now propagate
  to the host instead of being reported as lost authorization — which reached
  the person enrolling as "your link expired" for what might be a database
  problem, with nothing in any log. `false` is reserved for genuine
  authorization or counter loss; the conformance suite pins the distinction on
  all three adapters. (#6)
- The SQLite adapter runs every transaction with `BEGIN IMMEDIATE`, removing
  the read-then-write shape that WAL cannot retry after another connection
  writes (`SQLITE_BUSY_SNAPSHOT`; `busy_timeout` does not apply there).
  **Custom drivers** implementing the `SqliteDatabase` shape must expose
  better-sqlite3's `transaction(fn).immediate()`.

### Changed

- `authCookieNames` and `cookieAttributes` now **throw** for a plain-HTTP
  `publicOrigin` that is not loopback (`localhost`, `*.localhost`, `127.0.0.1`,
  `[::1]`), instead of silently issuing non-`Secure` cookies. WebAuthn never
  runs on such origins, so the value was always a misconfiguration.
- `serializeCookie` validates the cookie name and value against RFC 6265 and
  throws `TypeError` on characters that would corrupt or inject headers.
- The channels Miniflare suite bundles and runs the real worker source
  (esbuild) instead of an inline copy; the starter's `/api/invite` returns 409
  for an already-invited email.

## 2.1.0 - 2026-08-05

### Added

- `revokeUserSessions(userId, { exceptSessionToken? })` on `LocalWebAuthn`:
  end every live session for a user without revoking credentials or enrollment
  grants — "sign out everywhere", or "sign out my other devices" when the
  caller's own token is excepted. Emits a new `user.sessions_revoked` audit
  event and returns the revoked count. (#1)
- **Custom store implementers:** the `LocalWebAuthnStore` contract gains a
  required method
  `revokeUserSessions(userId, now, idleExpiresBefore, exceptSessionHash?)`.
  The official SQLite, PostgreSQL, and D1 adapters implement it (single
  conditional `UPDATE`; no transaction required).
- `issueEnrollment` now returns `supersededGrantIds`, the pending grants it
  revoked by superseding them, so hosts can record the replacement durably from
  the return value; the `enrollment.revoked` events remain best-effort
  observability. (#3)

### Documentation

- Every method that refuses an inactive user (`getUser` returning
  `active: false`) now says so: `issueEnrollment`, `exchangeEnrollment`,
  `registrationOptions`, `verifyRegistration`, `verifyAuthentication`, and
  `resolveSession`. README and SECURITY.md state that `active: false` is the
  supported suspension switch. (#2)

## 2.0.0 - 2026-08-04

Major release. Upgrading from 1.0.0 or 1.1.0 is strongly recommended: those
versions delete passkeys during routine maintenance.

### Security

- **No credential cleanup.** 1.0.0–1.1.0 deleted credentials that had no session
  rows after one hour — the normal idle state after logout or session expiry.
  Deployments that scheduled `cleanup()` as documented could wipe idle users'
  passkeys. `cleanup()` now only reaps expired grants, finished challenges, and
  dead sessions. **BREAKING:** `CleanupResult.orphanedCredentials` is removed;
  there is no orphan-credential sweep.
- **Last-credential protection is now race-free on PostgreSQL.** The conditional
  `UPDATE` introduced with the store-side check is atomic on SQLite and D1,
  which serialize writers, but PostgreSQL's READ COMMITTED isolation let two
  concurrent revokes of different credentials each read the other as still
  active and both succeed, leaving the account with no passkeys. The PostgreSQL
  adapter now takes a row lock on the user's active credentials before
  evaluating the predicate.

### Changed

- **BREAKING (custom stores):** `revokeSession` returns
  `{ userId, credentialId } | null` instead of `boolean`, so audit events can
  carry session identity.
- **BREAKING (custom stores):** `revokeCredential` accepts
  `{ allowLastCredential?: boolean }` and returns
  `'revoked' | 'not_found' | 'last_credential'`. Last-credential protection is
  enforced in the store (atomic with the revoke on SQLite/PostgreSQL).
- Host applications using only the official adapters and `LocalWebAuthn` service
  API need no integration changes for the store signature updates.
- `session.revoked` audit events now include `userId` and `credentialId`.
- `revokeUserAuthentication` emits `user.authentication_revoked`.
- Signature counter advances reject non-increasing non-zero values at both the
  service and store layers (0→0 remains allowed).
- SQLite `migrateSqlite` and `SqliteLocalWebAuthnStore` enable
  `PRAGMA foreign_keys = ON` on the given connection.

### Documentation

- SECURITY.md and package README describe durable credentials vs ephemeral
  cleanup, and correct the prior claim that “orphaned” credentials could not
  authenticate.
- `docs/MIGRATING.md` covers 1.1.x → 2.0.0 store contract changes.
- Review notes: `docs/REVIEW-20260804.md`.

### Note on versioning

These store-contract changes are breaking, so this is a major release. An
earlier draft shipped them as `1.2.0` alongside a narrowed SemVer promise that
excluded the store interface; that promise has been restored to its original
form — the service API, store interface, and database schema all follow SemVer,
and breaking changes arrive only in a major version.

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
