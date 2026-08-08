# Migrating LocalWebAuthn

## 2.2.0 → unreleased (credential kinds and machine credentials)

### Schema version 2

The schema moves from 1 to 2, in one step. `migrateSqlite`, `migratePostgres` and
`migrateD1` now read the stored version and apply only what is missing, so calling them on
a 1.x database upgrades it in place. Adding a column is why that machinery had to exist —
`CREATE TABLE IF NOT EXISTS` cannot do it.

Version 2 adds:

- `localwebauthn_credentials.kind` — nullable, host-defined credential class.
- `localwebauthn_challenges.credential_kind` — the kind a registration ceremony creates.
- `localwebauthn_challenges.allowed_credential_kinds` — JSON array of kinds an
  authentication ceremony accepts; `NULL` is unconstrained.
- `localwebauthn_enrollment_grants.credential_kind` — the kind a bootstrap token may
  create.
- `localwebauthn_dpop_proofs` — the DPoP `jti` replay cache.
- `localwebauthn_dpop_nonces` — server-issued DPoP nonces, keyed by time slot.
- `localwebauthn_credential_kind_idx` on `(user_id, kind, revoked_at)`.
- `localwebauthn_active_grant_user_idx` re-scoped from `(user_id)` to
  `(user_id, COALESCE(credential_kind, ''))`. `COALESCE` is required: NULLs are distinct
  in a unique index on both engines, so indexing the bare column would silently drop the
  one-pending-grant invariant for the default kind — which is every grant a host that
  ignores kinds ever issues. This is the one statement that has to drop and recreate
  rather than being additive.

This landed as four versions during development, collapsed to one before release. Version
1 is the only version ever published, so no database anywhere sits at an intermediate
version, and collapsing leaves a single upgrade path to write, test and read.

No `CHECK` constraints were added. SQLite cannot add one to an existing table, and a fresh
install must not end up with constraints an upgraded install lacks — the two would diverge
and only one of them would be tested. The equivalent invariants live in the service layer.

`tests/server/migrations.test.ts` upgrades a database built from the literal released v1
DDL and asserts it ends up with the same tables, columns and indexes as a fresh install,
that existing rows survive with the new columns `NULL`, and that re-running the migration
is a no-op.

Two traps if you extend this. `LOCALWEBAUTHN_SCHEMA_SQL` must contain **no `--`
comments**: the statement splitter collapses whitespace, which joins a comment to the
statement after it and comments the whole thing out — D1 reports "SQL code did not contain
a statement". And a new _table_ needs no entry in `LOCALWEBAUTHN_MIGRATIONS`, because
`localWebAuthnUpgradeStatements` lifts its `CREATE TABLE IF NOT EXISTS` out of the full
schema in the right dialect; only columns and index changes need explicit statements.

**Every existing credential keeps `kind: NULL`**, and an undeclared kind behaves exactly as
before, so a deployment that ignores all of this sees no behaviour change.

### Custom `LocalWebAuthnStore` implementations

Add one method:

```ts
claimDpopProof(jtiHash: Uint8Array, expiresAt: number): Promise<boolean>;
```

Record the digest if absent and return `true`; return `false` if it was already there,
which is a replayed proof. Must be atomic — two concurrent requests carrying the same `jti`
must not both see `true`. Official adapters use `SQL.claimDpopProof`. Two more for server-issued DPoP nonces (RFC 9449 section 8):

```ts
claimDpopNonce(slot: number, candidate: string, expiresAt: number): Promise<string>;
dpopNonces(currentSlot: number, previousSlot: number): Promise<string[]>;
```

`claimDpopNonce` inserts `candidate` for `slot` if unclaimed and returns the **stored**
value — never `candidate` — so every server in a deployment converges on one nonce per
slot. The primary key is the only coordination: whichever server inserts first decides,
and the rest read it back. That is why the nonce lives in the database rather than in
memory; an in-memory value would be rejected by whichever server the client did not
happen to reach first.

Nonces are stored in the clear, unlike every other token in this schema. They are not
secrets — the server hands the current one to any caller in a response header. The only
property needed is that a _future_ one cannot be guessed.

`CleanupResult` gains `dpopProofs` and `dpopNonces`, reaped with
`SQL.deleteExpiredDpopProofs` and `SQL.deleteExpiredDpopNonces`.

Four records grow by a column each, and the shared SQL already selects and binds them:

- `Credential` → `kind: string | null`
- `ChallengeRecord` / `ConsumedChallenge` → `credentialKind`, `allowedCredentialKinds`
- `SessionIdentity` → `credentialKind`, from the credential `SQL.selectSession` already joins

**One behaviour change.** `SQL.revokeCredential` and `SQL.isLastActiveCredential` scope the
last-credential guard to the credential's own kind, via `COALESCE(kind, '')` so pre-`kind`
rows form a single group. The change is monotone — never weaker than before, and
byte-identical for any user whose credentials all share one kind — but stricter in one new
case: revoking the last credential _of a kind_ now requires `allowLastCredential: true`.
Without it, a person holding one passkey and one API credential could have their only
passkey revoked and be told it worked.

### New service API

Nothing is required, but machine credentials need these:

```ts
// The kind is fixed by the host route, before the client ever sees a challenge.
registrationOptions({ sessionToken, credentialKind: 'service' });
// Restrict a ceremony to named kinds.
authenticationOptions({ credentialKinds: ['service'] });
// Declare policy per kind. Undeclared kinds keep the old permissive behaviour.
new LocalWebAuthn({
  credentialKinds: { service: { interactive: false, canRegister: false } },
});
```

Both bulk revoke methods now take a kind filter:

```ts
revokeUserSessions(userId, { kinds: ['person'] }); // sign the person out, keep the export
revokeUserAuthentication(userId, { kinds: ['service'] }); // revoke machine access only
```

Two things to know about the scoped form of `revokeUserAuthentication`. It revokes
pending enrollment grants **of the named kinds** — a live grant of kind X is standing
authorization to create another credential of kind X, so leaving one would let the
holder re-enroll straight back in — while grants of other kinds and all unconsumed
challenges are untouched. And it is **not a lockout**: a surviving credential of another
kind still authenticates as that user, so suspend through `getUser` returning
`active: false` if that is the intent.

Custom stores add two methods for these paths: `revokeLiveCredentialSessions`, which the
filtered session revoke loops over rather than binding a variable-length `IN (...)` the
shared static SQL cannot express, and `revokePendingEnrollmentGrants(userId, now, kind)`.

An enrollment grant now carries the kind it is authorized to create, and that binding
is what confines the token:

```ts
issueEnrollment(userId, { credentialKind: 'service' }); // options form
issueEnrollment(userId, 'admin-1'); // legacy positional approvedByUserId still works
```

This closes a fail-open default rather than an attack. Previously the class was chosen
by whichever route the token was redeemed at, and the ordinary human registration route
passes none — so a grant issued for a script produced `kind: null`, an unrestricted
credential, bypassing `interactive: false`, `canRegister: false`, machine-only routes
and kind-scoped revocation all at once. Since an enrollment token is a bearer secret in
transit to a machine, anyone who obtained it could pick the class. The grant's kind now
wins, and a route asking for a different one raises `invalid_configuration` rather than
losing silently. A grant that declares nothing still defers to the route.

It is **not** the self-replication fix. That remains `canRegister` on the session path,
plus the host refusing non-interactive kinds at its session middleware.

Custom stores: `EnrollmentGrantRecord` and `EnrollmentSession` gain `credentialKind`,
and `SQL.revokePendingGrants` takes a third bind for it so replacing a person's pending
link cannot cancel a pending deployment-key grant.

`verifyRegistration` deliberately takes **no** kind input — a client must not be able to
classify itself. `RegistrationVerificationResult` and `AuthenticationVerificationResult`
now report `credentialKind`, as does `SessionIdentity`.

`registrationOptions` refuses a session whose kind is declared `canRegister: false`, with
the new `registration_not_permitted` code. That closes a hole older than this release: any
live session could authorize registering another credential, so a leaked machine key could
mint a spare and outlive revocation of the first, making revocation useless as a remedy.

### Hosts must gate their session middleware on credential kind

`canRegister: false` closes the _session_ registration path. It cannot close the
_grant_ path — that one is authorized by possession of a single-use enrollment token
with no session involved, so the package has no `credentialKind` to inspect and no way
to tell a person from a program.

So a host that accepts machine credentials **must** refuse them at its cookie-session
middleware, or this chain reopens self-replication:

```
machine session token -> presented as a Cookie -> POST .../enrollment
  -> enrollment token -> exchange -> registrationOptions({ enrollmentSessionToken })
  -> a new credential, canRegister:false bypassed
```

`SessionIdentity.credentialKind` and `auth.config.credentialKinds` are both public, so
the check is two lines. The demo reuses the kind's own `interactive` declaration: a
kind that may not open a session at the browser login route may not use one at a
browser route either.

### New service API, continued

`verifyDpop` verifies an RFC 9449 proof against the session's credential. There is no
per-session key material to store: the expected thumbprint is derived from
`credentials.public_key`.

Server-issued nonces are **opt-in**, because they cost the client something real — it must
retain the latest `DPoP-Nonce` and retry once when challenged. `@localwebauthn/client`
already does both; a hand-written client would have to.

```ts
new LocalWebAuthn({ dpopNonce: { rotationMs: 5 * 60_000 } }); // enables issuance
await auth.dpopNonce(); // current nonce, or null when unconfigured
await auth.verifyDpop({ ..., requireNonce: true }); // enforce
```

A proof with no nonce, or a stale one, throws the new `dpop_nonce_required` code so the
host can answer `401` with `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a fresh
`DPoP-Nonce` header. Current _and_ previous slot are accepted, so a rotation landing
mid-flight does not reject a proof built moments earlier. Asking for `requireNonce`
without `dpopNonce` configured is an `invalid_configuration` error rather than a silent
pass.

The nonce is per **deployment**, not per credential or per session: its only job is to be
unguessable in advance, and rotation on a clock delivers that globally. It is also the one
element of a per-request proof the _server_ chooses — `jti`, `iat`, `htm`, `htu` and the
key are all the client's — which is what makes it the part that stops a key holder
pre-generating proofs. Note that a nonce is deliberately **reusable** within its window,
unlike `jti`, which is single-use and is why the replay cache exists.

## 2.1.0 → 2.2.0

No changes are required for applications using the official SQLite, PostgreSQL,
or D1 adapters and the `LocalWebAuthn` service API. Two things to know:

**Custom `SqliteDatabase` drivers must expose `transaction(fn).immediate()`.**
The SQLite adapter now opens every transaction with `BEGIN IMMEDIATE`, so
concurrent connections queue at the write lock instead of failing with an
unretryable `SQLITE_BUSY_SNAPSHOT` mid-transaction. better-sqlite3 provides
this already; a hand-written driver must add it. Set `PRAGMA busy_timeout` on
the connection you pass so a contended `BEGIN` waits rather than erroring.

**Storage faults now propagate instead of being reported as lost
authorization.** `completeRegistration` and `completeAuthentication` previously
turned _any_ exception into `false`, which the service rendered as
`registration_failed` — telling people their valid enrollment link had expired
and leaving nothing in any log. `false` is now reserved for genuine
authorization or counter-CAS loss; everything else throws. If your route
handler only mapped `LocalWebAuthnError`, an unexpected storage error will now
surface as an unhandled exception (a 500 in most frameworks) rather than a 409
— which is the point, but check that your error middleware logs it.

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
