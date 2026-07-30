# LocalWebAuthn

**Default to passkeys, not password plumbing.**

[![npm server](https://img.shields.io/npm/v/@localwebauthn/server?label=server)](https://www.npmjs.com/package/@localwebauthn/server)
[![npm browser](https://img.shields.io/npm/v/@localwebauthn/browser?label=browser)](https://www.npmjs.com/package/@localwebauthn/browser)
[![CI](https://github.com/LocalWebAuthn/LocalWebAuthn/actions/workflows/ci.yml/badge.svg)](https://github.com/LocalWebAuthn/LocalWebAuthn/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/LocalWebAuthn/LocalWebAuthn)](LICENSE)

LocalWebAuthn is a self-hosted, invitation-first, passkey-only authentication lifecycle
for TypeScript applications. It gives a small application the parts normally missing
between WebAuthn ceremonies and an authenticated session: enrollment, credentials,
challenges, sessions, revocation, and SQLite or Cloudflare D1 persistence.

Your application keeps its users and authorization. It does not keep passwords, password
hashes, password reset tokens, TOTP seeds, or recovery codes. It stores public keys and
hashed opaque tokens instead, and no database value can be replayed as a passkey.

LocalWebAuthn is `0.x` software. Its APIs and schemas may change. Review
[SECURITY.md](SECURITY.md) before a production deployment.

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

Connect that table to LocalWebAuthn and choose a storage adapter:

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

The packages are HTTP-framework neutral. Your route adapter owns exact-origin checks,
HTTP-only `Secure` cookies, CSRF defenses, rate limits, and response mapping. The
[Hono demo adapter](examples/demo/src/auth.ts) is a complete reference implementation,
not hidden framework behavior. Production WebAuthn requires HTTPS, with a browser-defined
exception for localhost development.

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
| SQLite and D1 authentication schemas           | LocalWebAuthn  |
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
  conforming SQLite and Cloudflare D1 stores.
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
not require a long-lived npm write token. See [docs/RELEASING.md](docs/RELEASING.md).
