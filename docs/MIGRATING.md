# Migrating LocalWebAuthn

## 2.0.0 → 2.1.0

No changes are required for applications using the official SQLite, PostgreSQL,
or D1 adapters and the `LocalWebAuthn` service API.

**Custom `LocalWebAuthnStore` implementations** must add one method:

```ts
revokeUserSessions(
  userId: string,
  now: number,
  idleExpiresBefore: number,
  exceptSessionHash?: Uint8Array,
): Promise<number>;
```

Revoke every live session for the user — not revoked, `expires_at > now`,
`last_seen_at > idleExpiresBefore` (the same predicates `resolveSession`
applies) — skip the session whose token hash equals `exceptSessionHash` when
given, and return the number of sessions revoked. A single conditional `UPDATE`
suffices; no transaction is required. The store conformance suite pins the
required behavior.

**Exhaustive `LocalWebAuthnEvent` switches** gain one new member:
`user.sessions_revoked` (`{ at, userId, count }`), emitted by the new
`revokeUserSessions` service method.

`issueEnrollment` now also returns `supersededGrantIds`. Nothing to change,
but hosts that recorded grant replacement from the best-effort
`enrollment.revoked` event can now record it durably from the return value.

## 1.1.0 → 2.0.0

### Security fix: no credential cleanup

Versions 1.0.0–1.1.0 deleted credentials that had no session rows and were
older than one hour. That treated the normal idle state of a passkey (after
logout or session expiry) as garbage and could wipe every idle user's
credentials if operators scheduled `cleanup()` as documented.

**2.0.0 removes credential cleanup entirely.** `cleanup()` only reaps expired
grants, finished challenges, and dead sessions. The
`CleanupResult.orphanedCredentials` field is gone — there is no orphan-credential
sweep to report.

If you run `cleanup()` on a timer, upgrade immediately. No data migration is
required; credentials that were already deleted cannot be restored — those
users need re-enrollment.

### Custom `LocalWebAuthnStore` implementors

Two store methods change return types. Host applications that only use an
official adapter and the `LocalWebAuthn` service API need no code changes.

#### `revokeSession` returns identity

```ts
// 1.1.0
revokeSession(idHash, now): Promise<boolean>;

// 2.0.0
revokeSession(idHash, now): Promise<{ userId: string; credentialId: string } | null>;
```

Use `UPDATE … RETURNING user_id, credential_id` (or equivalent) so the service
can emit an audit event with the session identity.

#### `revokeCredential` enforces last-credential atomically

```ts
// 1.1.0
revokeCredential(userId, credentialId, now): Promise<boolean>;

// 2.0.0
revokeCredential(
  userId,
  credentialId,
  now,
  options?: { allowLastCredential?: boolean },
): Promise<'revoked' | 'not_found' | 'last_credential'>;
```

When `allowLastCredential` is not set, refuse to revoke the user's only
remaining active credential and return `"last_credential"`. Perform that check
in the same statement or transaction as the revoke.

#### New audit event

`revokeUserAuthentication` emits `user.authentication_revoked` with `userId`.
Handle it if you switch on `LocalWebAuthnEvent['type']`.

#### Counter advance rule

`completeAuthentication` must reject a non-increasing counter when either the
stored or new value is non-zero (0→0 remains allowed). The official SQL does
this in `advanceCredentialCounter`.

#### `CleanupResult` no longer has `orphanedCredentials`

```ts
// 1.1.0
type CleanupResult = {
  enrollmentGrants: number;
  challenges: number;
  sessions: number;
  orphanedCredentials: number;
};

// 2.0.0
type CleanupResult = {
  enrollmentGrants: number;
  challenges: number;
  sessions: number;
};
```

Do not delete credentials in `cleanup`.

#### Last-credential protection must be race-free

When `allowLastCredential` is false, `revokeCredential` must refuse to remove a
user's only active passkey — and that check has to be atomic with the revoke,
not a read followed by a write.

A single conditional `UPDATE` is enough on engines that serialize writers:

```sql
UPDATE localwebauthn_credentials
SET revoked_at = ?
WHERE id = ? AND user_id = ? AND revoked_at IS NULL
  AND (? = 1 OR EXISTS (
    SELECT 1 FROM localwebauthn_credentials AS other
    WHERE other.user_id = ? AND other.id <> ? AND other.revoked_at IS NULL))
```

**On PostgreSQL that is not sufficient.** Under the default READ COMMITTED
isolation the `EXISTS` sub-select does not block on another transaction's
uncommitted `UPDATE` of a different row, so two concurrent revokes of two
different credentials each see the other as still active and both succeed —
leaving the account with no passkeys. Take a row lock first, inside the same
transaction:

```sql
SELECT id FROM localwebauthn_credentials
WHERE user_id = $1 AND revoked_at IS NULL
ORDER BY id
FOR UPDATE
```

`ORDER BY id` keeps lock acquisition deterministic so two transactions on the
same user cannot deadlock. The official PostgreSQL adapter does this; a custom
MVCC-backed store needs the equivalent.

## 1.0.x → 1.1.0

Nothing to do. The `LocalWebAuthnStore` contract and every public type are
unchanged, so existing integrations and custom store implementations keep
working as-is.

To adopt PostgreSQL, install `pg` and swap the adapter — nothing else about your
integration changes:

```ts
import { Pool } from 'pg';
import { migratePostgres, PostgresLocalWebAuthnStore } from '@localwebauthn/server/postgres';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
await migratePostgres(pool);

const auth = new LocalWebAuthn({
  // ... unchanged
  store: new PostgresLocalWebAuthnStore(pool),
});
```

Pass a `Pool`, not a single `Client`: transactions need a connection to
themselves, and issuing `BEGIN` on a connection shared between concurrent
requests would interleave unrelated statements into the same transaction.

There is no data migration path between adapters. `migratePostgres` creates an
empty schema; it does not copy an existing SQLite database. Moving a live
deployment means re-enrolling users, because moving credentials between stores
is out of scope for this package.

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

In 1.0.0–1.1.0 this field reported credentials deleted by cleanup. **That
behavior was incorrect** (see [1.1.0 → 2.0.0](#110--200)): 2.0.0 removes the
field and all credential cleanup.

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
