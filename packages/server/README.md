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

Cloudflare Workers can use `D1LocalWebAuthnStore` and `migrateD1` from
`@localwebauthn/server/d1`.
