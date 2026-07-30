# Review Findings — 0.1.1 → 1.0.0

Comprehensive review of claims, implementation, tests, and documentation.

## Must Fix Before 1.0

### 1. D1 Store Lacks Transactional Atomicity

The SQLite store wraps multi-statement operations in explicit transactions.
D1's `batch()` does **not** provide atomicity — each statement executes
independently. The `#guardPreviousChange()` mechanism detects some failures by
checking `changes()` but cannot roll back already-committed statements within a
batch. In rare concurrent-failure scenarios, an orphaned credential row may be
created.

**Fix**: Document the limitation, add orphaned-credential cleanup to `cleanup()`.

### 2. `revokeUserAuthentication` Has No Service-Level Test

A security-critical method with no dedicated coverage beyond incidental demo
application tests.

**Fix**: Add a service test verifying all credentials, sessions, grants, and
challenges are revoked/invalidated.

### 3. No Audit Event for Implicit Grant Revocation

When `issueEnrollment` replaces a prior pending grant, no event is emitted.
The audit trail contains a gap.

**Fix**: Emit an `enrollment.revoked` (or similar) event when a prior grant
is implicitly revoked during `issueEnrollment`.

### 4. No API Reference Documentation

Types are well-structured but lack descriptive TSDoc comments. Developers must
read source to understand configuration options and store interface methods.

**Fix**: Add comprehensive TSDoc to `LocalWebAuthnOptions`, `LocalWebAuthnStore`,
and the `LocalWebAuthn` class public methods.

## Should Fix

### 5. Restructure D1 `completeRegistration` for Readability

The INSERT...SELECT...WHERE has 14 positional bind parameters — correct but
very hard to audit. A single off-by-one would be a security bug.

### 6. Demo Error Detection Depends on SQLite Error Strings

In `examples/demo/src/application.ts`, duplicate email detection parses
`error.message.includes('UNIQUE constraint failed')` — fragile across versions
and incompatible with D1.

### 7. No Migration Strategy Documentation

Schema versioning exists but there's no documented procedure for applying
future schema changes in production.

### 8. Missing Logger for Event-Emission Failures

The `onEvent` callback errors are silently caught. A configurable logger
would allow production deployments to detect audit-log failures.

### 9. `createChallenge` Doesn't Report Duplicate Key Conflicts

Both stores silently succeed or fail on duplicate challenge `id_hash` values.

### 10. CI Tests Only Node 24, Package Declares `>=22.14`

The minimum supported Node version isn't tested in CI.

## Nice to Have

- Redundant byte copy in `toWebAuthnCredential`
- `rpId` format validation in config normalization
- Cookie naming gap between SECURITY.md and demo
- Concurrent-access tests for WAL-mode SQLite
- Documented cleanup scheduling recommendations

## Summary

The architecture is sound, the security model is well-considered, and the
documentation is unusually good for a 0.1.1 release. The most significant
concern is the D1 store's reliance on batch non-atomicity. All other findings
represent normal maturation toward a 1.0 release.
