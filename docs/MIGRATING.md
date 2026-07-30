# Migrating LocalWebAuthn

## 0.1.x → 1.0.0

### Breaking Store-Interface Changes

Custom `LocalWebAuthnStore` implementations must be updated for two method
signature changes and one new result field.

#### `replaceEnrollmentGrant` returns revoked grant IDs

```ts
// 0.1.x
replaceEnrollmentGrant(record: EnrollmentGrantRecord): Promise<void>;

// 1.0.0
replaceEnrollmentGrant(record: EnrollmentGrantRecord): Promise<string[]>;
```

Return the IDs of any pending grants that were revoked by this operation.
Use `RETURNING id` (SQLite / D1) or an equivalent approach. Return an empty
array if no prior grants existed.

#### `createChallenge` returns insertion status

```ts
// 0.1.x
createChallenge(record: ChallengeRecord): Promise<void>;

// 1.0.0
createChallenge(record: ChallengeRecord): Promise<boolean>;
```

Use `INSERT OR IGNORE` and return `true` when a row was inserted, `false`
when a challenge with the same `idHash` already existed (collision).

#### `cleanup` result includes `orphanedCredentials`

```ts
// 0.1.x
type CleanupResult = {
  enrollmentGrants: number;
  challenges: number;
  sessions: number;
};

// 1.0.0
type CleanupResult = {
  enrollmentGrants: number;
  challenges: number;
  sessions: number;
  orphanedCredentials: number;
};
```

The new `orphanedCredentials` field reports how many credentials were removed
because they had no session rows and were created more than one hour ago.
These orphans can occur in D1 deployments when a mid-batch guard failure leaves
a credential row without a corresponding session.

### New Configuration Option: `logger`

```ts
const auth = new LocalWebAuthn({
  // ...
  logger: console, // default — warns when onEvent callback throws
  // logger: { warn: () => {}, error: () => {} },  // suppress in tests
});
```

In 0.1.x, errors thrown by the `onEvent` callback were silently swallowed.
In 1.0.0 they are forwarded to `logger.warn()` (defaults to `console`).

### New Audit Event: `enrollment.revoked`

When `issueEnrollment` is called for a user who already has a pending
(uncompleted) enrollment grant, the prior grant is implicitly revoked and an
`enrollment.revoked` event is emitted for each revoked grant. Applications
that handle `LocalWebAuthnEvent` in an `onEvent` callback should handle this
new event type.

### No Changes Required For

- Host applications using only `SqliteLocalWebAuthnStore` or
  `D1LocalWebAuthnStore` — both are updated.
- The browser package (`@localwebauthn/browser`) — no API changes.
- Route adapters and cookie handling — unchanged.
