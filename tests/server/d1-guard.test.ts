/**
 * Does a failed D1 batch get told apart from a broken database?
 *
 * The D1 adapter reports `false` from `complete*` when its row-count guard trips,
 * meaning a concurrent request won a race. Everything else must reach the host as
 * an exception. Getting that boundary wrong is not cosmetic: a misclassified
 * storage fault is reported to the caller as "your enrollment link expired", which
 * is issue #6 one layer down.
 *
 * D1 offers no error codes, so the boundary is drawn by what the error message
 * names, and these tests therefore run against **real D1** (Miniflare/workerd) and
 * the **real schema**. Synthetic error strings would prove nothing here — the first
 * attempt at this fix matched `CHECK constraint failed: localwebauthn_transaction_guard`,
 * a message D1 never emits, and its unit tests passed because they asserted the
 * same invented text.
 */
import { Miniflare } from 'miniflare';
import { afterAll, describe, expect, it } from 'vitest';

import type { CompleteRegistrationInput } from '../../packages/server/src/index.js';

import {
  type D1DatabaseLike,
  D1LocalWebAuthnStore,
  isD1TransactionGuardFailure,
  migrateD1,
} from '../../packages/server/src/d1.js';
import { D1_GUARD_COLUMN, D1_SQL } from '../../packages/server/src/queries.js';

const now = 1_000_000;

function bytes(value: number): Uint8Array {
  return new Uint8Array(32).fill(value);
}

const miniflares = new Set<Miniflare>();

afterAll(async () => {
  await Promise.all([...miniflares].map((miniflare) => miniflare.dispose()));
  miniflares.clear();
});

async function d1(): Promise<{ database: D1DatabaseLike; store: D1LocalWebAuthnStore }> {
  const miniflare = new Miniflare({
    compatibilityDate: '2026-07-29',
    d1Databases: ['AUTH'],
    modules: true,
    script: 'export default { fetch() { return new Response("ok"); } }',
  });
  miniflares.add(miniflare);
  const database = (await miniflare.getD1Database('AUTH')) as unknown as D1DatabaseLike;
  await migrateD1(database);
  return { database, store: new D1LocalWebAuthnStore(database) };
}

/** Run `statements` as one batch and return the error it raised, or null. */
async function batchError(
  database: D1DatabaseLike,
  statements: readonly string[],
): Promise<unknown> {
  try {
    await database.batch(statements.map((sql) => database.prepare(sql)));
    return null;
  } catch (error) {
    return error;
  }
}

function registrationInput(overrides: {
  registrationGeneration?: number | null;
  sessionExpiresAt?: number;
}): CompleteRegistrationInput {
  return {
    challenge: {
      kind: 'registration',
      challenge: 'registration-challenge',
      userId: 'user-1',
      grantId: 'grant-1',
      authorizationSessionHash: null,
      credentialKind: null,
      allowedCredentialKinds: null,
      registrationGeneration: overrides.registrationGeneration ?? 0,
    },
    enrollmentSessionHash: bytes(2),
    authenticatedSessionHash: null,
    credential: {
      id: 'credential-1',
      userId: 'user-1',
      publicKey: bytes(9),
      counter: 0,
      transports: ['internal'],
      deviceType: 'multiDevice',
      backedUp: true,
      label: 'Primary passkey',
      kind: null,
      createdVia: 'enrollment',
      parentCredentialId: null,
      grantId: 'grant-1',
      approvedByUserId: 'admin-1',
      createdAt: now,
    },
    session: {
      idHash: bytes(4),
      userId: 'user-1',
      credentialId: 'credential-1',
      authenticatedAt: now,
      // The schema requires expires_at > authenticated_at. An equal value is a
      // genuine storage fault, used below to prove it is not swallowed.
      expiresAt: overrides.sessionExpiresAt ?? now + 10_000,
      lastSeenAt: now,
    },
    now,
  };
}

/** A registered credential-1 plus its session, via the grant path. */
async function registered(store: D1LocalWebAuthnStore): Promise<void> {
  await store.replaceEnrollmentGrant({
    id: 'grant-1',
    userId: 'user-1',
    tokenHash: bytes(1),
    expiresAt: now + 10_000,
    approvedByUserId: 'admin-1',
    credentialKind: null,
    createdAt: now,
  });
  await store.exchangeEnrollment(bytes(1), bytes(2), now + 5_000, now);
  expect(await store.completeRegistration(registrationInput({}))).toBe(true);
}

describe('classifying a real D1 batch failure', () => {
  it('recognises a guard trip, and pins the message D1 actually produces', async () => {
    const { database } = await d1();
    const error = await batchError(database, [
      // Changes no rows: there is no such user, so the guard must abort the batch.
      `UPDATE localwebauthn_credentials SET counter = 1 WHERE id = 'absent'`,
      D1_SQL.guardPreviousChange,
    ]);

    expect(error).not.toBeNull();
    expect(isD1TransactionGuardFailure(error)).toBe(true);
    // Pin the real text. If D1 or SQLite ever rewords this, the classifier stops
    // recognising guard trips and starts throwing them — safe, but wrong — so this
    // assertion is what makes that a CI failure rather than a production surprise.
    expect(String(error)).toContain(`NOT NULL constraint failed: ${D1_GUARD_COLUMN}`);
  });

  it('recognises a fence trip, and passes when the fence still holds', async () => {
    const { database } = await d1();
    await database
      .prepare(
        `INSERT INTO localwebauthn_registration_fences(user_id, generation, updated_at)
         VALUES ('user-1', 7, ${String(now)})`,
      )
      .run();

    /** Run the fence guard for `expected`, returning the error or null. */
    async function fence(expected: number): Promise<unknown> {
      try {
        await database.batch([
          database.prepare(D1_SQL.guardRegistrationFence).bind('user-1', expected),
          database.prepare(D1_SQL.clearGuard),
        ]);
        return null;
      } catch (error) {
        return error;
      }
    }

    // A challenge issued at generation 0 while the fence now reads 7: a revoke
    // happened in between, so the batch must abort and be classified as a trip.
    const moved = await fence(0);
    expect(moved).not.toBeNull();
    expect(isD1TransactionGuardFailure(moved)).toBe(true);

    // The same statement must not abort when the generation still matches.
    expect(await fence(7)).toBeNull();
  });

  /**
   * Every other way the real schema can refuse a write. Each must be rethrown, so
   * the host sees a database problem as a database problem. The three `CHECK` rows
   * are the ones the previous bare `CHECK constraint failed` match got wrong.
   *
   * Each case also asserts the message it *expected* to provoke. Without that, a
   * case can rot into proving nothing: the first draft of this table wrote
   * `transports` instead of `transports_json`, so three cases failed with "no such
   * column" and passed for a reason that had nothing to do with constraints.
   */
  const credentialInsert = (columns: string, values: string): string =>
    `INSERT INTO localwebauthn_credentials(id, user_id, public_key, ${columns}, created_at)
     VALUES ('c-bad', ${values}, ${String(now)})`;

  it.each<[string, string, RegExp]>([
    [
      'CHECK on credentials.counter',
      credentialInsert(
        'counter, transports_json, device_type, backed_up, label',
        `'user-1', X'00', -1, '[]', 'multiDevice', 1, 'l'`,
      ),
      /CHECK constraint failed: counter >= 0/u,
    ],
    [
      'CHECK on credentials.device_type',
      credentialInsert(
        'counter, transports_json, device_type, backed_up, label',
        `'user-1', X'00', 0, '[]', 'notADeviceType', 1, 'l'`,
      ),
      /CHECK constraint failed: device_type/u,
    ],
    [
      'NOT NULL on another table',
      credentialInsert(
        'counter, transports_json, device_type, backed_up, label',
        `NULL, X'00', 0, '[]', 'multiDevice', 1, 'l'`,
      ),
      /NOT NULL constraint failed: localwebauthn_credentials\.user_id/u,
    ],
    [
      'CHECK on sessions.expires_at',
      `INSERT INTO localwebauthn_sessions(
         id_hash, user_id, credential_id, authenticated_at, expires_at, last_seen_at
       ) VALUES (X'${'bb'.repeat(32)}', 'user-1', 'c', ${String(now)}, ${String(now)}, ${String(now)})`,
      /CHECK constraint failed: expires_at > authenticated_at/u,
    ],
    [
      'foreign key on sessions.credential_id',
      `INSERT INTO localwebauthn_sessions(
         id_hash, user_id, credential_id, authenticated_at, expires_at, last_seen_at
       ) VALUES (X'${'aa'.repeat(32)}', 'user-1', 'no-such-credential',
                 ${String(now)}, ${String(now + 1)}, ${String(now)})`,
      /FOREIGN KEY constraint failed/u,
    ],
    ['unknown column', `SELECT this is not valid sql`, /no such column/u],
    [
      'missing table',
      `INSERT INTO localwebauthn_not_a_table(x) VALUES (1)`,
      /no such table: localwebauthn_not_a_table/u,
    ],
  ])('rethrows: %s', async (_label, statement, expected) => {
    const { database } = await d1();
    const error = await batchError(database, [statement]);
    expect(error).not.toBeNull();
    // The case provoked the failure it claims to be about, not some other one.
    expect(String(error)).toMatch(expected);
    expect(isD1TransactionGuardFailure(error)).toBe(false);
  });

  it('reads the message off `cause` as well, and shrugs at non-errors', () => {
    const wrapped = new Error('D1_ERROR: something', {
      cause: new Error(`NOT NULL constraint failed: ${D1_GUARD_COLUMN}`),
    });
    expect(isD1TransactionGuardFailure(wrapped)).toBe(true);
    expect(isD1TransactionGuardFailure(`NOT NULL constraint failed: ${D1_GUARD_COLUMN}`)).toBe(
      true,
    );

    // The match the old code made, which is what let real faults through.
    expect(isD1TransactionGuardFailure(new Error('CHECK constraint failed'))).toBe(false);
    expect(isD1TransactionGuardFailure(new Error('CHECK constraint failed: value = 1'))).toBe(
      false,
    );
    expect(isD1TransactionGuardFailure(undefined)).toBe(false);
    expect(isD1TransactionGuardFailure({ message: 'not an Error' })).toBe(false);
  });
});

describe('what the store reports', () => {
  it('reports a lost counter compare-and-swap as false', async () => {
    const { store } = await d1();
    await registered(store);

    // The credential is at counter 0; claim a stale previousCounter so the
    // conditional UPDATE changes no rows and the guard aborts the batch.
    const lost = await store.completeAuthentication({
      credentialId: 'credential-1',
      previousCounter: 99,
      newCounter: 100,
      session: {
        idHash: bytes(5),
        userId: 'user-1',
        credentialId: 'credential-1',
        authenticatedAt: now,
        expiresAt: now + 10_000,
        lastSeenAt: now,
      },
      now,
    });
    expect(lost).toBe(false);
  });

  it('throws — not false — when the batch fails for a real storage reason', async () => {
    const { store } = await d1();
    await registered(store);

    // The counter CAS succeeds, so the guard does not trip. The session row is
    // invalid (expires_at must exceed authenticated_at), which is a fault in what
    // the caller passed. Reporting `false` here would tell the host "authentication
    // lost a race" when the truth is "this write can never succeed".
    await expect(
      store.completeAuthentication({
        credentialId: 'credential-1',
        previousCounter: 0,
        newCounter: 1,
        session: {
          idHash: bytes(6),
          userId: 'user-1',
          credentialId: 'credential-1',
          authenticatedAt: now,
          expiresAt: now,
          lastSeenAt: now,
        },
        now,
      }),
    ).rejects.toThrow(/CHECK constraint failed/u);
  });

  it('reports a moved registration fence as false', async () => {
    const { database, store } = await d1();
    await store.replaceEnrollmentGrant({
      id: 'grant-1',
      userId: 'user-1',
      tokenHash: bytes(1),
      expiresAt: now + 10_000,
      approvedByUserId: 'admin-1',
      credentialKind: null,
      createdAt: now,
    });
    await store.exchangeEnrollment(bytes(1), bytes(2), now + 5_000, now);
    // A revoke advances the fence after the challenge was issued at generation 0.
    await database
      .prepare(
        `INSERT INTO localwebauthn_registration_fences(user_id, generation, updated_at)
         VALUES ('user-1', 1, ${String(now)})`,
      )
      .run();

    expect(await store.completeRegistration(registrationInput({}))).toBe(false);
    // And nothing committed: the credential insert was in the same batch.
    const credentials = await store.listCredentials('user-1', true);
    expect(credentials).toEqual([]);
  });

  it('throws when registration fails for a real storage reason', async () => {
    const { store } = await d1();
    await store.replaceEnrollmentGrant({
      id: 'grant-1',
      userId: 'user-1',
      tokenHash: bytes(1),
      expiresAt: now + 10_000,
      approvedByUserId: 'admin-1',
      credentialKind: null,
      createdAt: now,
    });
    await store.exchangeEnrollment(bytes(1), bytes(2), now + 5_000, now);

    await expect(
      store.completeRegistration(registrationInput({ sessionExpiresAt: now })),
    ).rejects.toThrow(/CHECK constraint failed/u);
  });

  it('leaves the guard table empty whether the batch commits or aborts', async () => {
    const { database, store } = await d1();
    await registered(store);

    async function guardRows(): Promise<number> {
      const row = await database
        .prepare(`SELECT COUNT(*) AS n FROM localwebauthn_transaction_guard`)
        .first<{ n: number }>();
      return row?.n ?? -1;
    }

    // Committed path: `registered` above ran a successful batch.
    expect(await guardRows()).toBe(0);

    // Aborted path: the whole batch rolls back, guard rows included.
    await store.completeAuthentication({
      credentialId: 'credential-1',
      previousCounter: 99,
      newCounter: 100,
      session: {
        idHash: bytes(7),
        userId: 'user-1',
        credentialId: 'credential-1',
        authenticatedAt: now,
        expiresAt: now + 10_000,
        lastSeenAt: now,
      },
      now,
    });
    expect(await guardRows()).toBe(0);
  });
});
