# LocalWebAuthn

**Default to passkeys, not password plumbing.**

[![npm server](https://img.shields.io/npm/v/@localwebauthn/server?label=server)](https://www.npmjs.com/package/@localwebauthn/server)
[![npm browser](https://img.shields.io/npm/v/@localwebauthn/browser?label=browser)](https://www.npmjs.com/package/@localwebauthn/browser)
[![CI](https://github.com/LocalWebAuthn/LocalWebAuthn/actions/workflows/ci.yml/badge.svg)](https://github.com/LocalWebAuthn/LocalWebAuthn/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/LocalWebAuthn/LocalWebAuthn)](LICENSE)

LocalWebAuthn is a self-hosted, invitation-first, passkey-only authentication lifecycle
for TypeScript applications. It gives a small application the parts normally missing
between WebAuthn ceremonies and an authenticated session: enrollment, credentials,
challenges, sessions, revocation, and SQLite, PostgreSQL, or Cloudflare D1 persistence.

Your application keeps its users and authorization. It does not keep passwords, password
hashes, password reset tokens, TOTP seeds, or recovery codes. It stores public keys and
hashed opaque tokens instead, and no database value can be replayed as a passkey.

LocalWebAuthn is `1.1.0`. The service API, store interface, and database schema follow
SemVer: breaking changes arrive only in a new major version, with upgrade notes in
[docs/MIGRATING.md](docs/MIGRATING.md).

A stable API is not a long production track record. This is young software with a small
user base, and it sits on the authentication path. Both packages together are about 3,300
lines of TypeScript, deliberately kept small enough to read — do that, and read
[SECURITY.md](SECURITY.md), before you depend on it.

## See The Whole Lifecycle

![Clone, start, and bootstrap the demo](docs/images/quickstart.gif)

The terminal recording ends where WebAuthn begins. The browser consumes the one-time
fragment, removes it from history, and asks the platform authenticator to create the
administrator's passkey.

Administrator enrollment:

![Administrator enrollment](docs/images/demo-enrollment.png)

Client creation, enrollment, passkey counts, and revocation:

![Client and enrollment management](docs/images/demo-administration.png)

The same authenticated client can maintain multiple passkeys:

<p align="center">
  <img
    src="docs/images/demo-passkeys-mobile.png"
    width="390"
    alt="Two passkeys registered for one authenticated client"
  >
</p>

Play the original terminal recording with `asciinema play docs/demo.cast`. The complete
browser lifecycle is an executable Playwright test using Chromium virtual passkeys:

```console
nix develop
make demo-test
```

The test bootstraps the administrator, creates a client, enrolls that client in a second
browser context, adds another passkey, signs out, and signs back in.

## Why Start With Passkeys?

A password field is not a small feature. It commits an application to password hashing,
password policy, reset and recovery flows, email delivery, credential-stuffing defenses,
breach response, and usually a second factor. A demonstration often ships the first pieces
and quietly inherits the rest as production risk.

A passkey starts with a different security property: the authenticator keeps the private
key and the relying party stores a public key. The browser and authenticator bind each
credential to the relying party, which makes WebAuthn resistant to phishing and removes the
server-side password verifier from a database breach. These are properties of the
[WebAuthn standard](https://www.w3.org/TR/webauthn-3/), not custom cryptography in this
package. See the [MDN WebAuthn overview](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
and [passkeys.dev](https://passkeys.dev/docs/) for accessible introductions.

| Password-first application                | LocalWebAuthn application                       |
| ----------------------------------------- | ----------------------------------------------- |
| Stores a slow password verifier           | Stores a credential ID and public key           |
| Accepts a reusable, phishable secret      | Verifies an origin-bound challenge signature    |
| Must prevent password reuse and stuffing  | Every credential is unique to the relying party |
| Needs reset tokens and a recovery channel | Needs an explicit re-enrollment/recovery policy |
| Often adds TOTP, SMS, or recovery codes   | Can require authenticator user verification     |
| Must maintain password-hashing parameters | Delegates standard ceremonies to SimpleWebAuthn |

Passkeys do not remove application security. A stolen active session or enrollment link is
still a bearer capability. A compromised server can alter code or hijack future sessions.
The database still contains user data, public-key credential metadata, and hashes of
session and enrollment tokens. A read-only database disclosure cannot produce a valid
passkey signature or recover the high-entropy bearer tokens, but database write access or
a full server compromise can still subvert authentication. Recovery and identity proofing
remain product policy. The narrower claim is the important one: **your server never
receives or stores a reusable user authentication secret.**

## Coming From Password Authentication

If you have built login with `bcrypt` and a session cookie, or wired up Passport,
NextAuth, or a hosted provider, most of what you know still applies. Sessions, cookies,
CSRF, and authorization are unchanged. Three things are different.

**Every password concept has a direct replacement.**

| Password application                        | LocalWebAuthn                                                        |
| ------------------------------------------- | -------------------------------------------------------------------- |
| `users.password_hash` column                | No such column; a public key lives in `localwebauthn_credentials`    |
| `bcrypt.hash(...)` when the user signs up   | `createUserHandle()`; the authenticator generates the key pair       |
| `bcrypt.compare(...)` when the user logs in | `auth.verifyAuthentication({ response, challengeToken })`            |
| "Forgot password" email with a reset token  | `auth.issueEnrollment(userId)` returns a one-time URL                |
| `req.session.userId = user.id`              | `auth.resolveSession(sessionToken)` returns the user                 |
| `req.session.destroy()`                     | `auth.revokeSession(sessionToken)`                                   |
| Force a reset after a leak                  | `auth.revokeCredential(...)` or `auth.revokeUserAuthentication(...)` |
| Bolt on TOTP for a second factor            | `userVerification: 'required'`; the authenticator does it            |

**Signing in takes two requests instead of one.** A password is a secret the client can
just send. A passkey proves possession of a private key, so the server issues a random
challenge first and verifies a signature over it second:

```text
password   POST /login          {username, password}   -> Set-Cookie: session

passkey    POST /login/options  {}                     -> challenge  + Set-Cookie: challenge
             (browser prompts for Touch ID, a security key, or the password manager)
           POST /login/verify   {signed assertion}     -> Set-Cookie: session
```

The challenge has to survive between those two requests. LocalWebAuthn hands your route a
`challengeToken` to put in a short-lived cookie, and stores only its hash server-side.

**Sign-in submits no username.** Passkeys are discoverable credentials: the authenticator
already knows which account it holds for your site, so the user picks it in the browser's
own UI. `POST /login/options` therefore takes an empty body. Practically, this means there
is no username-enumeration surface to defend, and no per-username rate limit to write —
rate limit the route instead.

The trade you are accepting is recovery. There is no "email me a reset link" that a
password system gives you for free, because there is no shared secret to reset. Recovery
means issuing a fresh enrollment link, which is an act of identity proofing your
application must define. Plan that before you ship, not after a user loses their phone.

## From User Row To Session

Install both packages:

```console
npm install @localwebauthn/server @localwebauthn/browser
```

Keep the identity fields your application actually needs. There is deliberately no
password column:

```sql
CREATE TABLE app_users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  webauthn_user_handle BLOB NOT NULL UNIQUE,
  active INTEGER NOT NULL DEFAULT 1
);
```

Connect that table to LocalWebAuthn and choose a storage adapter. SQLite:

```ts
import Database from 'better-sqlite3';
import { LocalWebAuthn } from '@localwebauthn/server';
import { migrateSqlite, SqliteLocalWebAuthnStore } from '@localwebauthn/server/sqlite';

const database = new Database('application.db');
migrateSqlite(database);

const auth = new LocalWebAuthn({
  rpName: 'Example',
  rpId: 'app.example.com',
  expectedOrigins: 'https://app.example.com',
  publicOrigin: 'https://app.example.com',
  store: new SqliteLocalWebAuthnStore(database),
  users: {
    async getUser(userId) {
      const user = await applicationUsers.get(userId);
      return (
        user && {
          id: user.id,
          name: user.email,
          displayName: user.displayName,
          webAuthnUserHandle: user.webAuthnUserHandle,
          active: user.active,
        }
      );
    },
  },
});
```

PostgreSQL and Cloudflare D1 are drop-in replacements for the `store` option. Pass a
`pg.Pool` rather than a single client, so transactions get a connection to themselves:

```ts
import { Pool } from 'pg';
import { migratePostgres, PostgresLocalWebAuthnStore } from '@localwebauthn/server/postgres';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
await migratePostgres(pool);

// ... store: new PostgresLocalWebAuthnStore(pool)
```

```ts
import { D1LocalWebAuthnStore, migrateD1 } from '@localwebauthn/server/d1';

await migrateD1(env.DB);

// ... store: new D1LocalWebAuthnStore(env.DB)
```

Each `migrate*` call is idempotent, so calling it on every start is fine. All three
adapters pass the same store conformance suite. SQLite and PostgreSQL use real
transactions; D1 cannot, and the [D1 section of SECURITY.md](SECURITY.md#d1-batch-non-atomicity)
explains what it does instead.

Create the application's user with `createUserHandle()`, then issue an enrollment:

```ts
import { createUserHandle } from '@localwebauthn/server';

const user = await applicationUsers.create({
  email: 'ada@example.com',
  displayName: 'Ada Lovelace',
  webAuthnUserHandle: createUserHandle(),
});

const { enrollmentUrl } = await auth.issueEnrollment(user.id);
```

Your application decides who may create users and how to deliver or approve that URL.
LocalWebAuthn makes it single-use, expiring, hashed at rest, and bound to exactly one user.
The same method can re-enroll an existing user after your recovery policy approves it.

The browser side consumes the URL fragment and runs the native ceremony:

```ts
import { consumeEnrollmentToken, LocalWebAuthnBrowser } from '@localwebauthn/browser';

const auth = new LocalWebAuthnBrowser();
const token = consumeEnrollmentToken(window.location, window.history);

if (token) {
  await auth.exchangeEnrollment(token);
  await auth.registerPasskey('Primary passkey');
} else {
  await auth.signIn();
}
```

An authenticated user adds another passkey with the same
`auth.registerPasskey('Security key')` call. No enrollment link is required.

### The Six Endpoints

`LocalWebAuthnBrowser` speaks a small JSON protocol over six routes that you implement.
There is no hidden framework behavior — these are the paths it POSTs to, and nothing
happens that your own handler did not do:

| Route (default)                      | Service call                  | Cookie it sets / clears                     |
| ------------------------------------ | ----------------------------- | ------------------------------------------- |
| `POST /api/auth/enrollment/exchange` | `exchangeEnrollment(token)`   | sets enrollment                             |
| `POST /api/auth/register/options`    | `registrationOptions({...})`  | sets challenge                              |
| `POST /api/auth/register/verify`     | `verifyRegistration({...})`   | clears challenge + enrollment, sets session |
| `POST /api/auth/login/options`       | `authenticationOptions()`     | sets challenge                              |
| `POST /api/auth/login/verify`        | `verifyAuthentication({...})` | clears challenge, sets session              |
| `POST /api/auth/logout`              | `revokeSession(token)`        | clears session                              |

Change the prefix with `new LocalWebAuthnBrowser({ basePath: '/auth' })`, or any
individual path with the `endpoints` option.

Three cookies are involved, all opaque, all hashed before storage, none readable by
JavaScript: a short-lived **challenge** cookie that lives only between an `options` call
and its `verify`, an **enrollment** cookie that lives from link exchange until the first
passkey exists, and the **session** cookie that is the actual login.

A complete adapter is about forty lines. In Hono:

```ts
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';

const cookie = (expiresAt?: number) => ({
  httpOnly: true,
  secure: true,
  sameSite: 'Strict' as const,
  path: '/',
  ...(expiresAt ? { maxAge: Math.ceil((expiresAt - Date.now()) / 1000) } : {}),
});

app.post('/api/auth/login/options', async (c) => {
  const { options, challengeToken, expiresAt } = await auth.authenticationOptions();
  setCookie(c, '__Host-challenge', challengeToken, cookie(expiresAt));
  return c.json(options);
});

app.post('/api/auth/login/verify', async (c) => {
  const challengeToken = getCookie(c, '__Host-challenge') ?? '';
  deleteCookie(c, '__Host-challenge', cookie());
  const result = await auth.verifyAuthentication({
    response: await c.req.json(),
    challengeToken,
  });
  setCookie(c, '__Host-session', result.sessionToken, cookie(result.expiresAt));
  return c.json({ verified: true });
});

// Guard your own routes:
app.use('/api/*', async (c, next) => {
  const resolved = await auth.resolveSession(getCookie(c, '__Host-session') ?? '');
  if (!resolved) return c.json({ error: 'unauthenticated' }, 401);
  c.set('user', resolved.user);
  await next();
});
```

Throw a `LocalWebAuthnError` into your error mapper and it carries a `code` and an HTTP
`status`, so failures become JSON responses without leaking why a ceremony failed.

The [Hono demo adapter](examples/demo/src/auth.ts) implements all six routes, plus
exact-origin enforcement and the enrollment flow. Your route layer owns origin checks,
CSRF defenses, and rate limits. Production WebAuthn requires HTTPS, with a
browser-defined exception for localhost development.

## What LocalWebAuthn Owns

LocalWebAuthn supplies the lifecycle rules and persistence that ceremony libraries leave
to each application:

| Concern                                        | Owner          |
| ---------------------------------------------- | -------------- |
| Application users, roles, and authorization    | Host           |
| Link approval, delivery, and identity proofing | Host           |
| Cookies, exact-origin checks, and rate limits  | Host           |
| Enrollment grants and atomic replay protection | LocalWebAuthn  |
| Registration and authentication challenges     | LocalWebAuthn  |
| Credential metadata, counters, and revocation  | LocalWebAuthn  |
| Session expiry, touch, logout, and revocation  | LocalWebAuthn  |
| SQLite, PostgreSQL, and D1 schemas             | LocalWebAuthn  |
| WebAuthn option generation and verification    | SimpleWebAuthn |

This boundary is intentional. Authentication lifecycle is reusable; identity proofing and
business authorization are application policy. See [Why LocalWebAuthn](docs/RATIONALE.md)
for the detailed rationale and non-goals.

## Run The Demo

```console
git clone https://github.com/LocalWebAuthn/LocalWebAuthn.git
cd LocalWebAuthn
nix develop
make demo
```

Open the administrator enrollment URL printed by the server. The demo listens only on
`http://localhost:4173` and stores its disposable SQLite database under
`examples/demo/.data/`.

It demonstrates:

- Initial administrator bootstrap with a one-time enrollment URL.
- Passkey-only sign-in and logout.
- Administrator-created users and enrollment links.
- Enrollment in another browser or on another device.
- Additional passkeys authorized by an authenticated session.
- Individual credential and whole-user authentication revocation.

See [examples/demo/README.md](examples/demo/README.md) for the code map and security
boundary. See [docs/DEMO.md](docs/DEMO.md) to reproduce the recording and screenshots.

## Good Fit

LocalWebAuthn fits applications that can require passkey-capable clients and want to own
their user records without running a password system or external identity provider. This
includes internal tools, admin surfaces, prototypes intended to become real systems, and
small production applications with a deliberate enrollment and recovery policy.

"Self-hosted" describes the relying-party application and its authentication data. A user
may choose an operating system, password manager, or hardware security key to hold the
private key, and a passkey provider may sync it between that user's devices. That provider
is not an identity provider for the application; LocalWebAuthn never receives the private
key.

Choose a mature identity provider instead when you need federation, enterprise directory
integration, regulated identity assurance, high-volume abuse operations, or account
recovery that your team cannot safely operate. Do not make passkey-only access mandatory
for a population whose devices or accessibility needs you have not validated.

## Packages

- [`@localwebauthn/server`](packages/server) provides the framework-neutral lifecycle and
  conforming SQLite, PostgreSQL, and Cloudflare D1 stores, exported from
  `/sqlite`, `/postgres`, and `/d1`.
- [`@localwebauthn/browser`](packages/browser) performs enrollment, registration,
  authentication, and logout through a small default HTTP protocol.

This repository is an npm workspace. Both public packages are versioned together.

```console
nix develop
make check
make demo-test
```

`make check` runs TypeScript, lint, formatting, unit and adapter conformance tests, package
builds, `publint`, and `arethetypeswrong`. Releases use npm OIDC Trusted Publishing and do
not require a long-lived npm write token. Publishing is triggered by a versioned GitHub
Release, not by an ordinary branch push. See [docs/RELEASING.md](docs/RELEASING.md) and
[CHANGELOG.md](CHANGELOG.md).
