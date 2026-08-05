# LocalWebAuthn Lifecycle Demo

A **simple, complete** local app that demonstrates passkey-only authentication
and invitation-based user management — without passwords and without a third-party
identity provider.

It uses:

- `@localwebauthn/server` with the SQLite adapter
- `@localwebauthn/browser` for browser ceremonies
- Hono for the HTTP and cookie adapter
- One application-owned `demo_clients` table
- Vite for static client assets

How this positions against ceremony libraries, auth frameworks, and IdPs:
[docs/COMPARISON.md](../../docs/COMPARISON.md).

## What you should notice

| Instead of…                  | This demo does…                                          |
| ---------------------------- | -------------------------------------------------------- |
| Password signup / login      | Passkey create + continue                                |
| "Forgot password" email      | Administrator **Re-enroll** (revoke, then one-time link) |
| "Stolen laptop" panic reset  | **Sign out everywhere** — sessions end, passkeys survive |
| Auth0 / Clerk / OIDC         | Auth runs in this process; users live in `demo_clients`  |
| Self-serve open registration | Invitation URLs printed or copied by an administrator    |

The application never writes LocalWebAuthn grants, challenges, credentials, or
sessions. Those tables belong to `SqliteLocalWebAuthnStore`.

## Start

```console
nix develop
make demo-reset
make demo
```

The server prints:

```text
Initial administrator enrollment URL:
http://localhost:4173/enroll#token=...
```

1. Open that URL and create the administrator passkey.
2. Use **Add person** to invite someone; copy the enrollment URL.
3. Open the URL in another browser profile or device; create their passkey.
4. While signed in, **Add passkey** registers another device (no new link).
5. **Sign out other devices** (your account) and the per-person **Sign out**
   action end sessions only — passkeys stay valid and the person just signs in
   again. Use these when a session, not a credential, is the problem.
6. **Re-enroll** revokes their passkeys and issues a recovery link (the
   documented recovery order).

`make demo-reset` removes only `examples/demo/.data/localwebauthn-demo.db`.

Visiting `/` without a passkey shows sign-in help pointing at the enrollment URL
— first credentials always come from an invitation, not from the bare homepage.

## Code map

| File                    | Responsibility                                                |
| ----------------------- | ------------------------------------------------------------- |
| `src/database.ts`       | App-owned `demo_clients` + package SQLite migration           |
| `src/auth.ts`           | Complete Hono adapter: origin check, cookies, six auth routes |
| `src/application.ts`    | Bootstrap, invite, re-enroll, revoke, session sign-out        |
| `src/client.ts`         | UI via `LocalWebAuthnBrowser` (no raw WebAuthn calls)         |
| `e2e/lifecycle.spec.ts` | Playwright + Chromium virtual passkeys                        |

## Test

```console
npx playwright install chromium
make demo-test
```

`make check` also runs API tests under `tests/application.test.ts` (bootstrap,
admin authorization, re-enroll).

## Security boundary

Binds to `127.0.0.1`, HTTP for localhost, enrollment secrets on the terminal.
Convenient for local review — **not** a production template.

Production still needs exact HTTPS origins, secure cookies, approved link
delivery, rate limits, audit persistence, and a real recovery policy. The demo
keeps those host duties visible rather than hiding them inside the package.
