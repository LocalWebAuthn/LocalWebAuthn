# Review Findings — 0.1.1 → 1.1.0

Comprehensive review of claims, implementation, tests, and documentation.
Status key: ✅ fixed ◷ deferred ✘ not started

## Must Fix Before 1.0

### ✅ 1. D1 Store Lacks Transactional Atomicity

The SQLite store wraps multi-statement operations in explicit transactions.
D1's `batch()` does **not** provide atomicity — each statement executes
independently. The `#guardPreviousChange()` mechanism detects some failures by
checking `changes()` but cannot roll back already-committed statements within a
batch. In rare concurrent-failure scenarios, an orphaned credential row may be
created.

**Done**: Documented the limitation in `SECURITY.md`. Both `cleanup()`
implementations now remove orphaned credentials (no session rows, created over
one hour ago). Conformance tests added for both SQLite and D1 stores.

### ✅ 2. `revokeUserAuthentication` Has No Service-Level Test

A security-critical method with no dedicated coverage beyond incidental demo
application tests.

**Done**: Service-level test verifies credentials, sessions, enrollment
grants, enrollment sessions, and challenges are all invalidated.

### ✅ 3. No Audit Event for Implicit Grant Revocation

When `issueEnrollment` replaces a prior pending grant, no event is emitted.
The audit trail contains a gap.

**Done**: `replaceEnrollmentGrant` now returns the IDs of revoked grants.
`issueEnrollment` emits an `enrollment.revoked` event for each implicitly
revoked prior grant. Test verifies the event is emitted and the old grant
becomes unusable.

### ✅ 4. No API Reference Documentation

Types are well-structured but lack descriptive TSDoc comments. Developers must
read source to understand configuration options and store interface methods.

**Done**: Comprehensive TSDoc added to `LocalWebAuthnOptions`, `LocalWebAuthnStore`
(all 14 methods), `AuthUser`, `UserProvider`, `Credential`, `SessionIdentity`,
and `LocalWebAuthn` class public methods. Comments surface in IDE intellisense
and generated `.d.ts` files.

## Should Fix

### ✅ 5. Restructure D1 `completeRegistration` for Readability

The INSERT...SELECT...WHERE had 19 positional bind parameters — correct but
very hard to audit. A single off-by-one would be a security bug.

**Done**: Parameters are now extracted to descriptively named locals, the SQL
documents the two mutually-exclusive authorization paths (grant vs. session),
and every `.bind()` parameter is labeled with its position and purpose.

**Superseded in 1.1.0**: the statement was split into two single-purpose
queries, so the labelled 19-parameter version no longer exists. See the second
pass below.

### ✅ 6. Demo Error Detection Depends on SQLite Error Strings

In `examples/demo/src/application.ts`, duplicate email detection parsed
`error.message.includes('UNIQUE constraint failed')` — fragile across versions
and incompatible with D1.

**Done**: Replaced with an explicit `clientByEmail()` pre-check before the
INSERT. The catch block now returns a generic 500 without inspecting error
messages.

### ✅ 7. No Migration Strategy Documentation

Schema versioning exists but there's no documented procedure for applying
future schema changes in production.

**Done** (1.1.0): `docs/MIGRATING.md` covers each version transition, and the
README states that every `migrate*` call is idempotent and safe to run on each
start. The migrations table records the applied schema version.

### ✅ 8. Missing Logger for Event-Emission Failures

The `onEvent` callback errors were silently caught. A configurable logger
allows production deployments to detect audit-log failures.

**Done**: Added `logger` option to `LocalWebAuthnOptions` (defaults to
`console`). `#emit` now calls `logger.warn()` with the event type and error
when the `onEvent` callback throws.

### ✅ 9. `createChallenge` Doesn't Report Duplicate Key Conflicts

Both stores silently succeeded or failed on duplicate challenge `id_hash`
values.

**Done**: `createChallenge` returns `boolean` (`INSERT OR IGNORE` +
`changes()` check). The service throws a `409` with a clear message on
collision (astronomically unlikely with 256-bit random tokens, but handled
defensively).

### ✅ 10. CI Tests Only Node 24, Package Declares `>=22.14`

The minimum supported Node version isn't tested in CI.

**Done** (1.1.0): the check job runs a `[22, 24]` matrix. This mattered more
than it looked — a stray Node 20 in the local environment produced a native
module ABI mismatch, confirming the declared floor is real and worth testing.

## Nice to Have

| Status | Item                                                                                                                                                                                                                        |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ✅     | `toWebAuthnCredential` byte copy — investigated; the `Uint8Array.from()` call is **necessary** for narrowing `ArrayBufferLike` to `ArrayBuffer` for SimpleWebAuthn type compatibility. Not a redundant copy. Comment added. |
| ✅     | `rpId` format validation — validates bare hostname via `new URL('https://' + rpId)` in `config.ts`.                                                                                                                         |
| ◷      | Cookie naming gap between SECURITY.md and demo — `__Host-` prefix requires HTTPS; demo is localhost. The README adapter example now uses `__Host-` names.                                                                   |
| ◷      | Concurrent-access tests for WAL-mode SQLite — current in-memory test serialises implicitly.                                                                                                                                 |
| ✅     | Documented cleanup scheduling recommendations — SECURITY.md now asks for a periodic `cleanup()` (every few minutes) under "Storage Adapter Guarantees".                                                                     |

## Discovered During Implementation

- **D1 Miniflare emulation expands `Uint8Array` iterables** as multiple bind
  parameters. The orphaned-credential conformance test avoids raw BLOB INSERTs
  and instead uses the store interface to create credentials with
  already-expired sessions, then verifies `cleanup()` removes them. The
  `StoreFixture` type was extended with an optional `rawDb` for
  test-manipulation of underlying state.

- **`cleanup()` statement ordering matters**: sessions must be deleted before
  the orphaned-credential pass runs, otherwise active-session rows hide
  credentials whose sessions just expired. Both store implementations now
  order deletions correctly.

- **`replaceEnrollmentGrant` return type changed** from `Promise<void>` to
  `Promise<string[]>` so the service can emit per-grant audit events. This is
  a breaking change for custom `LocalWebAuthnStore` implementations, acceptable
  in 0.x per the README stability policy.

- **Config coverage dipped slightly** with the new `rpId` validation branches
  (`try`/`catch` and hostname mismatch). These are simple defensive checks;
  explicit error-path tests can be added when coverage thresholds are next
  raised.

## Second Pass (1.1.0)

A follow-up review targeted the developer coming from password authentication,
PostgreSQL support, and simplification.

**Documentation gap found.** The browser client POSTs to six endpoints that the
host must implement, and nothing outside `packages/browser/src/index.ts`
enumerated them. A developer could install both packages, call `auth.signIn()`,
and get a 404 with no documented way to learn which routes to build. The README
now has an endpoint table, the cookies each route sets, and a complete adapter.
A "Coming From Password Authentication" section maps each password concept to
its replacement and explains the two-request ceremony and the absent username.

**Simplifications applied.**

- Every SQL statement moved into `packages/server/src/queries.ts`. One
  definition per query to audit rather than one per adapter, and the SQLite and
  D1 adapters lost ~590 lines between them with no behavior change.
- SQLite `exchangeEnrollment` and `consumeChallenge` became single
  `UPDATE ... RETURNING` statements instead of `SELECT`-then-`UPDATE` inside a
  transaction — the same guarantee with the TOCTOU window removed rather than
  papered over.
- The D1 credential insert went from one 19-parameter statement branching on
  `? IS NOT NULL` to two single-purpose statements. The caller already knows
  which authorization path applies, so the SQL no longer has to.
- `StoreFixture.rawDb` was dead after the 1.0.0 orphan-test rewrite; removed.

**Discovered during PostgreSQL work.**

- `pg-mem` is unusable for this adapter: it inlines a `Buffer` bind parameter as
  an empty string and lacks `octet_length`. Byte-array hashes are the core data
  type here, so testing against it would have produced confident, wrong results.
  PostgreSQL conformance therefore requires a real server — provisioned by
  `flake.nix` locally and a service container in CI.
- node-postgres returns `BIGINT` as a string. The row mappers coerce, and reject
  anything that will not round-trip as a safe integer rather than truncating a
  timestamp or counter silently.
- `$N IS NOT NULL` fails in PostgreSQL with "could not determine data type of
  parameter". This is what motivated splitting the D1 query rather than adding
  casts, which turned a portability obstacle into a readability win.
- CI sets `LOCALWEBAUTHN_REQUIRE_POSTGRES=1` so an unreachable server fails the
  run. Without it a misconfigured service container would skip the PostgreSQL
  suite and still report green.

## Summary

Every Must Fix and Should Fix item is now closed. One nice-to-have remains open:
concurrent-access tests for WAL-mode SQLite, where the current in-memory fixture
serialises implicitly and so does not exercise real contention.

The codebase is measurably more robust than at 0.1.1: 52 tests (up from 30)
across three storage adapters, one auditable home for all SQL, orphaned-credential
cleanup, audit-event completeness, validated configuration, and TSDoc on every
public interface.
