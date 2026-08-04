# `@localwebauthn/server`

Framework-neutral, self-hosted passkey enrollment and authentication built on
`@simplewebauthn/server`.

```ts
import { createUserHandle, LocalWebAuthn } from '@localwebauthn/server';
import { migrateSqlite, SqliteLocalWebAuthnStore } from '@localwebauthn/server/sqlite';

migrateSqlite(database);

const auth = new LocalWebAuthn({
  rpName: 'Example',
  rpId: 'app.example.com',
  expectedOrigins: 'https://app.example.com',
  store: new SqliteLocalWebAuthnStore(database),
  users: {
    async getUser(userId) {
      const user = await applicationUsers.get(userId);
      return user
        ? {
            id: user.id,
            name: user.email,
            displayName: user.name,
            webAuthnUserHandle: user.webAuthnUserHandle,
            active: user.active,
          }
        : null;
    },
  },
});

const userHandle = createUserHandle();
const enrollment = await auth.issueEnrollment('application-user-id');
```

The package deliberately does not prescribe an HTTP framework. Route handlers translate
cookies and JSON into the service methods. See the repository security policy before
deploying.

## Storage adapters

All three pass the same conformance suite and are interchangeable via the `store` option.

| Import                           | Store                        | Migration         |
| -------------------------------- | ---------------------------- | ----------------- |
| `@localwebauthn/server/sqlite`   | `SqliteLocalWebAuthnStore`   | `migrateSqlite`   |
| `@localwebauthn/server/postgres` | `PostgresLocalWebAuthnStore` | `migratePostgres` |
| `@localwebauthn/server/d1`       | `D1LocalWebAuthnStore`       | `migrateD1`       |

```ts
import { Pool } from 'pg';
import { migratePostgres, PostgresLocalWebAuthnStore } from '@localwebauthn/server/postgres';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
await migratePostgres(pool);
// store: new PostgresLocalWebAuthnStore(pool)
```

`better-sqlite3` and `pg` are optional peer dependencies — install only the one you use.
Pass a `pg.Pool` rather than a single client so transactions get their own connection.

SQLite and PostgreSQL wrap multi-statement operations in real transactions. D1 cannot, and
guards each step on the preceding row count instead; see the D1 section of the repository
security policy, and schedule periodic `cleanup()` there.

The SQLite adapter uses `UPDATE ... RETURNING`, which requires SQLite 3.35 or newer.

The repository's [lifecycle demo](../../examples/demo/README.md) shows the complete SQLite
integration, HTTP-only cookie adapter, initial bootstrap, client enrollment, additional
passkeys, and revocation.
