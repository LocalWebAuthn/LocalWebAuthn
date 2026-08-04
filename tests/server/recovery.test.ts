import Database from 'better-sqlite3';
import { beforeEach, describe, expect, it } from 'vitest';

import type { AuthUser, LocalWebAuthnEvent } from '../../packages/server/src/index.js';
import { createUserHandle, LocalWebAuthn } from '../../packages/server/src/index.js';
import { migrateSqlite, SqliteLocalWebAuthnStore } from '../../packages/server/src/sqlite.js';

/**
 * Recovery is the flow the README's "Designing Recovery" section walks through.
 * These tests pin the two behaviors that section tells implementers to rely on.
 */
describe('recovery flow', () => {
  let database: Database.Database;
  let user: AuthUser;
  let events: LocalWebAuthnEvent[];
  let auth: LocalWebAuthn;

  beforeEach(() => {
    database = new Database(':memory:');
    database.pragma('foreign_keys = ON');
    migrateSqlite(database);
    user = {
      id: 'user-1',
      webAuthnUserHandle: createUserHandle(() => new Uint8Array(32).fill(11)),
      name: 'user@example.test',
      displayName: 'Test User',
      active: true,
    };
    events = [];
    auth = new LocalWebAuthn({
      rpName: 'LocalWebAuthn Test',
      rpId: 'localhost',
      expectedOrigins: 'http://localhost:5173',
      store: new SqliteLocalWebAuthnStore(database),
      users: { getUser: async (id) => (id === user.id ? user : null) },
      onEvent: (event) => {
        events.push(event);
      },
    });
  });

  it('revoke-then-issue leaves the recovery link usable', async () => {
    await auth.revokeUserAuthentication(user.id);
    const issued = await auth.issueEnrollment(user.id, 'administrator-1');

    await expect(auth.exchangeEnrollment(issued.enrollmentToken)).resolves.toMatchObject({
      user: { id: user.id },
    });
    database.close();
  });

  it('issue-then-revoke destroys the link, which is why order matters', async () => {
    const issued = await auth.issueEnrollment(user.id, 'administrator-1');
    await auth.revokeUserAuthentication(user.id);

    await expect(auth.exchangeEnrollment(issued.enrollmentToken)).rejects.toMatchObject({
      code: 'invalid_enrollment',
    });
    database.close();
  });

  it('records the approving administrator against the issued grant', async () => {
    const issued = await auth.issueEnrollment(user.id, 'administrator-1');

    const grant = database
      .prepare('SELECT approved_by_user_id FROM localwebauthn_enrollment_grants WHERE id = ?')
      .get(issued.grantId) as { approved_by_user_id: string | null };
    expect(grant.approved_by_user_id).toBe('administrator-1');

    // The audit event carries the grantId that joins back to that record.
    expect(events).toContainEqual(
      expect.objectContaining({
        type: 'enrollment.issued',
        userId: user.id,
        grantId: issued.grantId,
      }),
    );
    database.close();
  });
});
