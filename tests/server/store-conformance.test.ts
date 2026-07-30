import type { AuthenticatorTransportFuture, Base64URLString } from '@simplewebauthn/server';

import Database from 'better-sqlite3';
import { Miniflare } from 'miniflare';
import { afterAll, describe, expect, it } from 'vitest';

import type {
  ChallengeRecord,
  CompleteRegistrationInput,
  LocalWebAuthnStore,
} from '../../packages/server/src/index.js';
import {
  type D1DatabaseLike,
  D1LocalWebAuthnStore,
  migrateD1,
} from '../../packages/server/src/d1.js';
import type { SqliteDatabase } from '../../packages/server/src/sqlite.js';
import { migrateSqlite, SqliteLocalWebAuthnStore } from '../../packages/server/src/sqlite.js';

type StoreFixture = {
  store: LocalWebAuthnStore;
  /** Direct database access for test setup (e.g., simulating batch failures). */
  rawDb: SqliteDatabase | D1DatabaseLike;
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
    rawDb: database as unknown as SqliteDatabase,
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
    rawDb: database,
    close: async () => {
      miniflares.delete(miniflare);
      await miniflare.dispose();
    },
  };
}

afterAll(async () => {
  await Promise.all([...miniflares].map(async (miniflare) => miniflare.dispose()));
});

function storeConformance(name: string, createFixture: () => Promise<StoreFixture>) {
  describe(`${name} store`, () => {
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

        await expect(
          fixture.store.revokeCredential('user-1', 'credential-1', now + 1),
        ).resolves.toBe(true);
        await expect(fixture.store.resolveSession(bytes(4), now + 2, now - 1)).resolves.toBeNull();
        await expect(fixture.store.listCredentials('user-1')).resolves.toHaveLength(0);
        await expect(fixture.store.listCredentials('user-1', true)).resolves.toMatchObject([
          { revokedAt: now + 1 },
        ]);
      } finally {
        await fixture.close();
      }
    });

    it('cleans up orphaned credentials whose sessions have all been expired or revoked', async () => {
      const fixture = await createFixture();
      try {
        // Create a legitimate credential with a non-expired session.
        await exchangedGrant(fixture.store);
        expect(await fixture.store.completeRegistration(registrationInput('grant-1'))).toBe(true);

        // Create a second credential whose session has already expired.
        // The credential must be older than the 1-hour orphan grace period.
        const grant2 = await exchangedGrant(fixture.store, 'grant-2', 10, 11);
        if (!grant2) {
          throw new Error('Second enrollment grant was not created.');
        }
        const expiredSessionNow = now - 4_000_000; // well past the 1-hour grace period
        const secondReg: CompleteRegistrationInput = {
          challenge: {
            kind: 'registration',
            challenge: 'registration-challenge',
            userId: 'user-1',
            grantId: 'grant-2',
            authorizationSessionHash: null,
          },
          enrollmentSessionHash: grant2.sessionHash,
          authenticatedSessionHash: null,
          credential: {
            ...credential('credential-2'),
            createdAt: expiredSessionNow,
          },
          session: {
            idHash: bytes(12),
            userId: 'user-1',
            credentialId: 'credential-2',
            authenticatedAt: expiredSessionNow,
            expiresAt: expiredSessionNow + 1, // already expired relative to cleanup now
            lastSeenAt: expiredSessionNow,
          },
          now: expiredSessionNow,
        };
        expect(await fixture.store.completeRegistration(secondReg)).toBe(true);

        // Both credentials exist.
        const allBefore = await fixture.store.listCredentials('user-1', true);
        expect(allBefore).toHaveLength(2);

        // cleanup() with a time well after the expired session: the session is removed,
        // and the credential (created long ago with no remaining sessions) should also be removed.
        const cleanupTime = now + 60_000;
        await fixture.store.cleanup(cleanupTime);

        const allAfter = await fixture.store.listCredentials('user-1', true);
        // credential-1 has an active session and survives; credential-2 is orphaned.
        expect(allAfter).toHaveLength(1);
        expect(allAfter[0].id).toBe('credential-1');
      } finally {
        await fixture.close();
      }
    });
  });
}

storeConformance('SQLite', sqliteFixture);
storeConformance('D1', d1Fixture);
