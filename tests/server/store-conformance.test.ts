import type { AuthenticatorTransportFuture, Base64URLString } from '@simplewebauthn/server';

import Database from 'better-sqlite3';
import { Miniflare } from 'miniflare';
import pg from 'pg';
import { afterAll, describe, expect, it } from 'vitest';

import type {
  ChallengeRecord,
  CompleteRegistrationInput,
  LocalWebAuthnDpopStore,
  LocalWebAuthnStore,
} from '../../packages/server/src/index.js';

/**
 * Every official adapter implements both contracts, so conformance tests the
 * intersection. A custom store may implement only {@link LocalWebAuthnStore}; the
 * service then refuses DPoP with `invalid_configuration` rather than failing to
 * typecheck.
 */
type ConformingStore = LocalWebAuthnStore & LocalWebAuthnDpopStore;
import {
  type D1DatabaseLike,
  D1LocalWebAuthnStore,
  migrateD1,
} from '../../packages/server/src/d1.js';
import {
  migratePostgres,
  type PostgresPool,
  PostgresLocalWebAuthnStore,
} from '../../packages/server/src/postgres.js';
import { migrateSqlite, SqliteLocalWebAuthnStore } from '../../packages/server/src/sqlite.js';

type StoreFixture = {
  store: ConformingStore;
  close(): Promise<void>;
};

const now = 1_000_000;

function bytes(value: number): Uint8Array {
  return new Uint8Array(32).fill(value);
}

function credential(id: string, userId = 'user-1') {
  return {
    id: id as Base64URLString,
    userId,
    publicKey: bytes(9),
    counter: 0,
    transports: ['internal'] as AuthenticatorTransportFuture[],
    deviceType: 'multiDevice' as const,
    backedUp: true,
    label: 'Primary passkey',
    kind: null,
    createdVia: 'enrollment' as const,
    parentCredentialId: null,
    grantId: 'grant-1',
    approvedByUserId: 'admin-1',
    createdAt: now,
  };
}

function enrollmentChallenge(grantId: string): ChallengeRecord {
  return {
    idHash: bytes(3),
    kind: 'registration',
    challenge: 'registration-challenge',
    userId: 'user-1',
    grantId,
    authorizationSessionHash: null,
    credentialKind: null,
    allowedCredentialKinds: null,
    registrationGeneration: 0,
    expiresAt: now + 1_000,
    createdAt: now,
  };
}

async function exchangedGrant(
  store: LocalWebAuthnStore,
  id = 'grant-1',
  tokenByte = 1,
  sessionByte = 2,
) {
  await store.replaceEnrollmentGrant({
    id,
    userId: 'user-1',
    tokenHash: bytes(tokenByte),
    expiresAt: now + 10_000,
    approvedByUserId: 'admin-1',
    credentialKind: null,
    createdAt: now,
  });
  return store.exchangeEnrollment(bytes(tokenByte), bytes(sessionByte), now + 5_000, now);
}

function registrationInput(grantId: string): CompleteRegistrationInput {
  return {
    challenge: {
      kind: 'registration',
      challenge: 'registration-challenge',
      userId: 'user-1',
      grantId,
      authorizationSessionHash: null,
      credentialKind: null,
      allowedCredentialKinds: null,
      registrationGeneration: 0,
    },
    enrollmentSessionHash: bytes(2),
    authenticatedSessionHash: null,
    credential: credential('credential-1'),
    session: {
      idHash: bytes(4),
      userId: 'user-1',
      credentialId: 'credential-1',
      authenticatedAt: now,
      expiresAt: now + 10_000,
      lastSeenAt: now,
    },
    now,
  };
}

async function sqliteFixture(): Promise<StoreFixture> {
  const database = new Database(':memory:');
  database.pragma('foreign_keys = ON');
  migrateSqlite(database);
  return {
    store: new SqliteLocalWebAuthnStore(database),
    close: async () => {
      database.close();
    },
  };
}

const miniflares = new Set<Miniflare>();

async function d1Fixture(): Promise<StoreFixture> {
  const miniflare = new Miniflare({
    compatibilityDate: '2026-07-29',
    d1Databases: ['AUTH'],
    modules: true,
    script: 'export default { fetch() { return new Response("ok"); } }',
  });
  miniflares.add(miniflare);
  const database = (await miniflare.getD1Database('AUTH')) as unknown as D1DatabaseLike;
  await migrateD1(database);
  return {
    store: new D1LocalWebAuthnStore(database),
    close: async () => {
      miniflares.delete(miniflare);
      await miniflare.dispose();
    },
  };
}

/**
 * PostgreSQL runs against a real server; there is no faithful in-process
 * emulator (pg-mem, for instance, mangles BYTEA parameters, which is precisely
 * the type every token hash uses). Start one with `pg-start` in the nix
 * devShell, or let CI's service container provide it. When no server is
 * reachable the suite skips rather than fails.
 */
const postgresUrl = process.env.LOCALWEBAUTHN_TEST_POSTGRES_URL;

async function postgresIsReachable(): Promise<boolean> {
  if (!postgresUrl) {
    return false;
  }
  const pool = new pg.Pool({ connectionString: postgresUrl, connectionTimeoutMillis: 2000 });
  try {
    await pool.query('SELECT 1');
    return true;
  } catch {
    return false;
  } finally {
    await pool.end().catch(() => undefined);
  }
}

async function postgresFixture(): Promise<StoreFixture> {
  const pool = new pg.Pool({ connectionString: postgresUrl });
  await migratePostgres(pool as unknown as PostgresPool);
  // Each fixture starts from an empty schema; tests in a file run sequentially.
  await pool.query(`TRUNCATE
    localwebauthn_sessions,
    localwebauthn_credentials,
    localwebauthn_challenges,
    localwebauthn_enrollment_grants,
    localwebauthn_registration_fences
    RESTART IDENTITY CASCADE`);
  return {
    store: new PostgresLocalWebAuthnStore(pool as unknown as PostgresPool),
    close: async () => {
      await pool.end();
    },
  };
}

afterAll(async () => {
  await Promise.all([...miniflares].map(async (miniflare) => miniflare.dispose()));
});

function storeConformance(
  name: string,
  createFixture: () => Promise<StoreFixture>,
  options: { skip?: boolean } = {},
) {
  const suite = options.skip ? describe.skip : describe;
  suite(`${name} store`, () => {
    it('fences a registration whose generation the store has moved on from', async () => {
      // The registration fence, which every adapter must enforce inside the same
      // transaction that commits the credential. Registration spans two requests
      // with a passkey ceremony in between, so the authorization checked when the
      // challenge was issued cannot be re-checked in one transaction — the
      // generation stamped on the challenge is the optimistic-concurrency version
      // that stands in for it.
      const fixture = await createFixture();
      try {
        // A fresh user starts at generation 0 and the read is idempotent.
        expect(await fixture.store.registrationGeneration('user-1', now)).toBe(0);
        expect(await fixture.store.registrationGeneration('user-1', now)).toBe(0);

        // Bumping is strictly monotonic: two bumps never yield the same value.
        const first = await fixture.store.bumpRegistrationGeneration('user-1', now);
        const second = await fixture.store.bumpRegistrationGeneration('user-1', now);
        expect(first).toBe(1);
        expect(second).toBe(2);
        expect(await fixture.store.registrationGeneration('user-1', now)).toBe(2);

        // A registration carrying a stale generation must not commit, even though
        // its grant and enrollment session are still perfectly valid.
        await exchangedGrant(fixture.store);
        const stale = registrationInput('grant-1');
        stale.challenge = { ...stale.challenge, registrationGeneration: 1 };
        expect(await fixture.store.completeRegistration(stale)).toBe(false);
        await expect(fixture.store.listCredentials('user-1')).resolves.toEqual([]);

        // The same registration at the current generation commits.
        const current = registrationInput('grant-1');
        current.challenge = { ...current.challenge, registrationGeneration: 2 };
        expect(await fixture.store.completeRegistration(current)).toBe(true);
        await expect(fixture.store.listCredentials('user-1')).resolves.toHaveLength(1);
      } finally {
        await fixture.close();
      }
    });

    it('walks credential heritage in both directions', async () => {
      const fixture = await createFixture();
      try {
        // root <- child <- grandchild, plus a sibling of child under root.
        await exchangedGrant(fixture.store);
        await fixture.store.completeRegistration(registrationInput('grant-1'));
        const link = async (id: string, parent: string, byte: number) => {
          await fixture.store.completeRegistration({
            ...registrationInput('grant-1'),
            challenge: {
              kind: 'registration',
              challenge: 'registration-challenge',
              userId: 'user-1',
              grantId: null,
              authorizationSessionHash: bytes(4),
              credentialKind: null,
              allowedCredentialKinds: null,
              registrationGeneration: 0,
            },
            enrollmentSessionHash: null,
            authenticatedSessionHash: bytes(4),
            credential: {
              ...credential(id),
              createdVia: 'credential' as const,
              parentCredentialId: parent,
              grantId: null,
              approvedByUserId: null,
            },
            session: {
              idHash: bytes(byte),
              userId: 'user-1',
              credentialId: id,
              authenticatedAt: now,
              expiresAt: now + 10_000,
              lastSeenAt: now,
            },
          });
        };
        await link('credential-2', 'credential-1', 20);
        await link('credential-3', 'credential-2', 21);
        await link('credential-sibling', 'credential-1', 22);

        // Ancestry is root first, so the enrollment-derived credential leads.
        const ancestry = await fixture.store.credentialAncestry('user-1', 'credential-3');
        expect(ancestry.map((entry) => entry.id)).toEqual([
          'credential-1',
          'credential-2',
          'credential-3',
        ]);
        expect(ancestry[0]).toMatchObject({ createdVia: 'enrollment', grantId: 'grant-1' });

        // Descendants include the subject at index 0 and exclude the sibling.
        const subtree = await fixture.store.credentialDescendants('user-1', 'credential-2');
        expect(subtree.map((entry) => entry.id)).toEqual(['credential-2', 'credential-3']);

        const whole = await fixture.store.credentialDescendants('user-1', 'credential-1');
        expect(whole.map((entry) => entry.id).sort()).toEqual([
          'credential-1',
          'credential-2',
          'credential-3',
          'credential-sibling',
        ]);

        // Scoped by user, and quiet about credentials that do not exist.
        await expect(fixture.store.credentialAncestry('other', 'credential-3')).resolves.toEqual(
          [],
        );
        await expect(fixture.store.credentialDescendants('user-1', 'nope')).resolves.toEqual([]);
      } finally {
        await fixture.close();
      }
    });

    it('converges on one DPoP nonce per slot', async () => {
      const fixture = await createFixture();
      try {
        // Two servers derive the same slot from their clocks and each offer their
        // own candidate. Whichever insert wins, both must read back the same
        // value — otherwise a client's nonce would be rejected by whichever
        // server it did not talk to first, which is the whole reason this lives
        // in the database rather than in memory.
        const [first, second] = await Promise.all([
          fixture.store.claimDpopNonce(1000, 'from-server-a', now + 60_000),
          fixture.store.claimDpopNonce(1000, 'from-server-b', now + 60_000),
        ]);
        expect(first).toBe(second);
        expect(['from-server-a', 'from-server-b']).toContain(first);

        // A later read is stable, and a different slot is a different nonce.
        await expect(
          fixture.store.claimDpopNonce(1000, 'from-server-c', now + 60_000),
        ).resolves.toBe(first);
        const next = await fixture.store.claimDpopNonce(1001, 'next-slot', now + 60_000);
        expect(next).toBe('next-slot');

        // Current plus previous slot are both accepted, so a rotation landing
        // mid-flight does not reject a proof built moments earlier.
        const accepted = await fixture.store.dpopNonces(1001, 1000);
        expect([...accepted].sort()).toEqual([first, next].sort());

        // An unclaimed slot contributes nothing rather than erroring.
        await expect(fixture.store.dpopNonces(9999, 9998)).resolves.toEqual([]);
      } finally {
        await fixture.close();
      }
    });

    it('reaps expired DPoP nonces and proofs', async () => {
      const fixture = await createFixture();
      try {
        await fixture.store.claimDpopNonce(1, 'stale', now - 1);
        await fixture.store.claimDpopNonce(2, 'live', now + 60_000);
        expect(await fixture.store.claimDpopProof(bytes(30), now - 1)).toBe(true);

        const result = await fixture.store.cleanup(now);
        expect(result.dpopNonces).toBe(1);
        expect(result.dpopProofs).toBe(1);
        await expect(fixture.store.dpopNonces(2, 1)).resolves.toEqual(['live']);
      } finally {
        await fixture.close();
      }
    });

    it('exchanges enrollment grants exactly once', async () => {
      const fixture = await createFixture();
      try {
        const exchange = await exchangedGrant(fixture.store);
        expect(exchange).toMatchObject({ grantId: 'grant-1', userId: 'user-1' });
        await expect(
          fixture.store.exchangeEnrollment(bytes(1), bytes(8), now + 5_000, now),
        ).resolves.toBeNull();
        await expect(fixture.store.resolveEnrollmentSession(bytes(2), now)).resolves.toMatchObject({
          grantId: 'grant-1',
        });
      } finally {
        await fixture.close();
      }
    });

    it('reports a duplicate challenge id instead of overwriting one', async () => {
      const fixture = await createFixture();
      try {
        await exchangedGrant(fixture.store);
        await expect(fixture.store.createChallenge(enrollmentChallenge('grant-1'))).resolves.toBe(
          true,
        );
        // Same id_hash, different challenge value: must not replace the original.
        await expect(
          fixture.store.createChallenge({
            ...enrollmentChallenge('grant-1'),
            challenge: 'a-different-challenge',
          }),
        ).resolves.toBe(false);
        await expect(
          fixture.store.consumeChallenge(bytes(3), 'registration', now),
        ).resolves.toMatchObject({ challenge: 'registration-challenge' });
      } finally {
        await fixture.close();
      }
    });

    it('consumes typed challenges exactly once', async () => {
      const fixture = await createFixture();
      try {
        await exchangedGrant(fixture.store);
        await fixture.store.createChallenge(enrollmentChallenge('grant-1'));

        await expect(
          fixture.store.consumeChallenge(bytes(3), 'authentication', now),
        ).resolves.toBeNull();
        await expect(
          fixture.store.consumeChallenge(bytes(3), 'registration', now),
        ).resolves.toMatchObject({
          grantId: 'grant-1',
          userId: 'user-1',
        });
        await expect(
          fixture.store.consumeChallenge(bytes(3), 'registration', now),
        ).resolves.toBeNull();
      } finally {
        await fixture.close();
      }
    });

    it('atomically completes the exact enrollment grant and creates a session', async () => {
      const fixture = await createFixture();
      try {
        await exchangedGrant(fixture.store);
        await expect(
          fixture.store.completeRegistration(registrationInput('grant-1')),
        ).resolves.toBe(true);
        await expect(fixture.store.listCredentials('user-1')).resolves.toHaveLength(1);
        await expect(
          fixture.store.resolveSession(bytes(4), now + 1, now - 1),
        ).resolves.toMatchObject({
          userId: 'user-1',
          credentialId: 'credential-1',
        });
        await expect(
          fixture.store.completeRegistration({
            ...registrationInput('grant-1'),
            credential: credential('credential-2'),
          }),
        ).resolves.toBe(false);
        await expect(fixture.store.listCredentials('user-1')).resolves.toHaveLength(1);
      } finally {
        await fixture.close();
      }
    });

    it('invalidates an exchanged ceremony when its grant is replaced', async () => {
      const fixture = await createFixture();
      try {
        await exchangedGrant(fixture.store);
        await fixture.store.replaceEnrollmentGrant({
          id: 'grant-2',
          userId: 'user-1',
          tokenHash: bytes(7),
          expiresAt: now + 20_000,
          approvedByUserId: 'admin-1',
          credentialKind: null,
          createdAt: now + 1,
        });

        await expect(
          fixture.store.completeRegistration(registrationInput('grant-1')),
        ).resolves.toBe(false);
        await expect(fixture.store.listCredentials('user-1')).resolves.toHaveLength(0);
      } finally {
        await fixture.close();
      }
    });

    it('allows only one concurrent counter update', async () => {
      const fixture = await createFixture();
      try {
        await exchangedGrant(fixture.store);
        expect(await fixture.store.completeRegistration(registrationInput('grant-1'))).toBe(true);

        const attempts = await Promise.all([
          fixture.store.completeAuthentication({
            credentialId: 'credential-1',
            previousCounter: 0,
            newCounter: 1,
            now: now + 1,
            session: {
              idHash: bytes(5),
              userId: 'user-1',
              credentialId: 'credential-1',
              authenticatedAt: now + 1,
              expiresAt: now + 10_000,
              lastSeenAt: now + 1,
            },
          }),
          fixture.store.completeAuthentication({
            credentialId: 'credential-1',
            previousCounter: 0,
            newCounter: 1,
            now: now + 1,
            session: {
              idHash: bytes(6),
              userId: 'user-1',
              credentialId: 'credential-1',
              authenticatedAt: now + 1,
              expiresAt: now + 10_000,
              lastSeenAt: now + 1,
            },
          }),
        ]);

        expect(attempts.filter(Boolean)).toHaveLength(1);
        expect((await fixture.store.getCredential('credential-1'))?.counter).toBe(1);
      } finally {
        await fixture.close();
      }
    });

    it('revokes credentials and their sessions together', async () => {
      const fixture = await createFixture();
      try {
        await exchangedGrant(fixture.store);
        expect(await fixture.store.completeRegistration(registrationInput('grant-1'))).toBe(true);

        // A second credential so last-credential protection does not block the revoke.
        const grant2 = await exchangedGrant(fixture.store, 'grant-2', 10, 11);
        if (!grant2) {
          throw new Error('Second enrollment grant was not created.');
        }
        expect(
          await fixture.store.completeRegistration({
            ...registrationInput('grant-2'),
            enrollmentSessionHash: grant2.sessionHash,
            credential: credential('credential-2'),
            session: {
              idHash: bytes(12),
              userId: 'user-1',
              credentialId: 'credential-2',
              authenticatedAt: now,
              expiresAt: now + 10_000,
              lastSeenAt: now,
            },
          }),
        ).toBe(true);

        await expect(
          fixture.store.revokeCredential('user-1', 'credential-1', now + 1),
        ).resolves.toBe('revoked');
        await expect(fixture.store.resolveSession(bytes(4), now + 2, now - 1)).resolves.toBeNull();
        await expect(fixture.store.listCredentials('user-1')).resolves.toMatchObject([
          { id: 'credential-2' },
        ]);
        await expect(fixture.store.listCredentials('user-1', true)).resolves.toEqual(
          expect.arrayContaining([
            expect.objectContaining({ id: 'credential-1', revokedAt: now + 1 }),
            expect.objectContaining({ id: 'credential-2', revokedAt: null }),
          ]),
        );
      } finally {
        await fixture.close();
      }
    });

    it('refuses to revoke the last active credential unless recovery allows it', async () => {
      const fixture = await createFixture();
      try {
        await exchangedGrant(fixture.store);
        expect(await fixture.store.completeRegistration(registrationInput('grant-1'))).toBe(true);

        await expect(
          fixture.store.revokeCredential('user-1', 'credential-1', now + 1),
        ).resolves.toBe('last_credential');
        await expect(fixture.store.listCredentials('user-1')).resolves.toHaveLength(1);

        await expect(
          fixture.store.revokeCredential('user-1', 'credential-1', now + 2, {
            allowLastCredential: true,
          }),
        ).resolves.toBe('revoked');
        await expect(fixture.store.listCredentials('user-1')).resolves.toHaveLength(0);
      } finally {
        await fixture.close();
      }
    });

    it('propagates real storage failures instead of reporting authorization loss', async () => {
      const fixture = await createFixture();
      try {
        await exchangedGrant(fixture.store);
        expect(await fixture.store.completeRegistration(registrationInput('grant-1'))).toBe(true);

        // Registering the SAME credential id again under a fresh, valid grant
        // is a genuine storage conflict (UNIQUE violation) — it must throw,
        // not masquerade as "authorization lost" / an expired enrollment.
        const grant2 = await exchangedGrant(fixture.store, 'grant-2', 10, 11);
        if (!grant2) {
          throw new Error('Second enrollment grant was not created.');
        }
        await expect(
          fixture.store.completeRegistration({
            ...registrationInput('grant-2'),
            enrollmentSessionHash: grant2.sessionHash,
            session: {
              idHash: bytes(14),
              userId: 'user-1',
              credentialId: 'credential-1',
              authenticatedAt: now,
              expiresAt: now + 10_000,
              lastSeenAt: now,
            },
          }),
        ).rejects.toThrow();

        // The authorization-lost case still reports `false`, not an error.
        await expect(
          fixture.store.completeRegistration(registrationInput('grant-1')),
        ).resolves.toBe(false);
      } finally {
        await fixture.close();
      }
    });

    it('revokes only live user sessions, sparing an excepted one', async () => {
      const fixture = await createFixture();
      try {
        await exchangedGrant(fixture.store);
        expect(await fixture.store.completeRegistration(registrationInput('grant-1'))).toBe(true);

        // A second live session (another device on the same passkey).
        expect(
          await fixture.store.completeAuthentication({
            credentialId: 'credential-1',
            previousCounter: 0,
            newCounter: 1,
            now: now + 1,
            session: {
              idHash: bytes(5),
              userId: 'user-1',
              credentialId: 'credential-1',
              authenticatedAt: now + 1,
              expiresAt: now + 10_000,
              lastSeenAt: now + 1,
            },
          }),
        ).toBe(true);

        // A stale session already past its absolute expiry at revoke time: it
        // must be neither revoked nor counted.
        expect(
          await fixture.store.completeAuthentication({
            credentialId: 'credential-1',
            previousCounter: 1,
            newCounter: 2,
            now: now + 2,
            session: {
              idHash: bytes(6),
              userId: 'user-1',
              credentialId: 'credential-1',
              authenticatedAt: now + 2,
              expiresAt: now + 50,
              lastSeenAt: now + 2,
            },
          }),
        ).toBe(true);

        // Spare bytes(5): only the registration session bytes(4) is live and unexcepted.
        await expect(
          fixture.store.revokeUserSessions('user-1', now + 100, now - 1, bytes(5)),
        ).resolves.toBe(1);
        await expect(
          fixture.store.resolveSession(bytes(4), now + 101, now - 1),
        ).resolves.toBeNull();
        await expect(
          fixture.store.resolveSession(bytes(5), now + 101, now - 1),
        ).resolves.not.toBeNull();

        // Without an exception the spared session goes too; repeat finds nothing.
        await expect(fixture.store.revokeUserSessions('user-1', now + 102, now - 1)).resolves.toBe(
          1,
        );
        await expect(
          fixture.store.resolveSession(bytes(5), now + 103, now - 1),
        ).resolves.toBeNull();
        await expect(fixture.store.revokeUserSessions('user-1', now + 104, now - 1)).resolves.toBe(
          0,
        );

        // Credentials are untouched by session revocation.
        await expect(fixture.store.listCredentials('user-1')).resolves.toHaveLength(1);
      } finally {
        await fixture.close();
      }
    });

    it('returns revoked session identity for audit and keeps credentials after cleanup', async () => {
      const fixture = await createFixture();
      try {
        await exchangedGrant(fixture.store);
        expect(await fixture.store.completeRegistration(registrationInput('grant-1'))).toBe(true);

        await expect(fixture.store.revokeSession(bytes(4), now + 1)).resolves.toEqual({
          userId: 'user-1',
          credentialId: 'credential-1',
        });
        // Idempotent: already revoked.
        await expect(fixture.store.revokeSession(bytes(4), now + 2)).resolves.toBeNull();

        // Cleanup reaps dead sessions only; credentials are not part of cleanup.
        const cleanupResult = await fixture.store.cleanup(now + 4_000_000);
        expect(cleanupResult.sessions).toBeGreaterThanOrEqual(1);
        await expect(fixture.store.listCredentials('user-1')).resolves.toHaveLength(1);

        // Authentication after cleanup still works (counter CAS + new session).
        await expect(
          fixture.store.completeAuthentication({
            credentialId: 'credential-1',
            previousCounter: 0,
            newCounter: 1,
            now: now + 4_000_001,
            session: {
              idHash: bytes(13),
              userId: 'user-1',
              credentialId: 'credential-1',
              authenticatedAt: now + 4_000_001,
              expiresAt: now + 5_000_000,
              lastSeenAt: now + 4_000_001,
            },
          }),
        ).resolves.toBe(true);
      } finally {
        await fixture.close();
      }
    });

    it('rejects a non-increasing non-zero signature counter', async () => {
      const fixture = await createFixture();
      try {
        await exchangedGrant(fixture.store);
        expect(await fixture.store.completeRegistration(registrationInput('grant-1'))).toBe(true);
        expect(
          await fixture.store.completeAuthentication({
            credentialId: 'credential-1',
            previousCounter: 0,
            newCounter: 5,
            now: now + 1,
            session: {
              idHash: bytes(5),
              userId: 'user-1',
              credentialId: 'credential-1',
              authenticatedAt: now + 1,
              expiresAt: now + 10_000,
              lastSeenAt: now + 1,
            },
          }),
        ).toBe(true);

        await expect(
          fixture.store.completeAuthentication({
            credentialId: 'credential-1',
            previousCounter: 5,
            newCounter: 5,
            now: now + 2,
            session: {
              idHash: bytes(6),
              userId: 'user-1',
              credentialId: 'credential-1',
              authenticatedAt: now + 2,
              expiresAt: now + 10_000,
              lastSeenAt: now + 2,
            },
          }),
        ).resolves.toBe(false);
        expect((await fixture.store.getCredential('credential-1'))?.counter).toBe(5);
      } finally {
        await fixture.close();
      }
    });
  });
}

const postgresReachable = await postgresIsReachable();

// CI sets this so an unreachable server is a failure rather than a silent skip;
// a green run there must mean PostgreSQL was actually exercised.
if (process.env.LOCALWEBAUTHN_REQUIRE_POSTGRES === '1' && !postgresReachable) {
  throw new Error(
    `LOCALWEBAUTHN_REQUIRE_POSTGRES=1 but no server was reachable at ${postgresUrl ?? '(unset LOCALWEBAUTHN_TEST_POSTGRES_URL)'}.`,
  );
}

storeConformance('SQLite', sqliteFixture);
storeConformance('D1', d1Fixture);
storeConformance('PostgreSQL', postgresFixture, { skip: !postgresReachable });

/**
 * PostgreSQL is the only engine where the last-credential predicate can race:
 * SQLite and D1 serialize writers, but MVCC lets two READ COMMITTED
 * transactions each read the other's credential as still active.
 *
 * A `Promise.all` of two revokes usually happens to serialize and so proves
 * nothing. This drives two connections through the exact interleaving instead,
 * which is what a real pair of concurrent requests can produce. Without
 * POSTGRES_SQL.lockUserCredentials both revokes succeed and the user is left
 * with no passkeys at all.
 */
describe.skipIf(!postgresReachable)('PostgreSQL concurrent revoke', () => {
  it('leaves one active credential when two revokes interleave', async () => {
    const pool = new pg.Pool({ connectionString: postgresUrl });
    await migratePostgres(pool as unknown as PostgresPool);
    await pool.query(`TRUNCATE localwebauthn_sessions, localwebauthn_credentials,
      localwebauthn_challenges, localwebauthn_enrollment_grants RESTART IDENTITY CASCADE`);

    const store = new PostgresLocalWebAuthnStore(pool as unknown as PostgresPool);
    for (const id of ['credential-a', 'credential-b']) {
      await pool.query(
        `INSERT INTO localwebauthn_credentials(
           id, user_id, public_key, counter, transports_json,
           device_type, backed_up, label, created_at)
         VALUES ($1, 'user-1', $2, 0, '[]', 'multiDevice', true, 'passkey', $3)`,
        [id, Buffer.from(bytes(9)), now],
      );
    }

    // Hold the user's credential rows on a third connection so both revokes
    // are guaranteed to be in flight at the same time before either can
    // proceed. Without the adapter's own lock neither call blocks here, both
    // read the other credential as active, and both succeed.
    const blocker = await pool.connect();
    let first: string;
    let second: string;
    try {
      await blocker.query('BEGIN');
      await blocker.query(
        `SELECT id FROM localwebauthn_credentials
         WHERE user_id = $1 AND revoked_at IS NULL ORDER BY id FOR UPDATE`,
        ['user-1'],
      );

      const a = store.revokeCredential('user-1', 'credential-a', now);
      const b = store.revokeCredential('user-1', 'credential-b', now);
      // Give both a chance to reach (and block on) the lock.
      await new Promise((resolve) => setTimeout(resolve, 100));
      await blocker.query('COMMIT');

      [first, second] = await Promise.all([a, b]);
    } finally {
      blocker.release();
    }

    // Exactly one succeeds; the other is refused as the last credential.
    expect([first, second].filter((result) => result === 'revoked')).toHaveLength(1);
    expect([first, second].filter((result) => result === 'last_credential')).toHaveLength(1);
    await expect(store.listCredentials('user-1')).resolves.toHaveLength(1);

    await pool.end();
  });
});
