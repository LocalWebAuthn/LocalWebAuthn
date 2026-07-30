# LocalWebAuthn Lifecycle Demo

This example is a complete local passkey application, not a mocked UI. It uses:

- `@localwebauthn/server` with the SQLite adapter.
- `@localwebauthn/browser` for browser ceremonies.
- Hono for the small HTTP and cookie adapter.
- One application-owned `demo_clients` table.
- Vite for static client assets.

## Start

```console
nix develop
make demo-reset
make demo
```

The server prints a URL similar to:

```text
Initial administrator enrollment URL:
http://localhost:4173/enroll#token=...
```

Open the URL, create the administrator passkey, then use **Add client**. Open the resulting
client URL in another browser profile or device to create that client's first passkey. Any
signed-in client can use **Add passkey** to register another passkey without an enrollment
link.

`make demo-reset` removes only the disposable database at
`examples/demo/.data/localwebauthn-demo.db`.

## Code Map

- `src/database.ts` creates the one application-owned client table and invokes the package
  SQLite migration.
- `src/auth.ts` is the complete Hono-to-LocalWebAuthn adapter: exact-origin enforcement,
  opaque HTTP-only cookies, and JSON mapping.
- `src/application.ts` contains demo policy: bootstrap, administrator-only client creation,
  enrollment issuance, and revocation.
- `src/client.ts` uses `LocalWebAuthnBrowser`; it contains no direct WebAuthn API calls.
- `e2e/lifecycle.spec.ts` verifies initial bootstrap, administrator enrollment, client
  creation, client enrollment, a second passkey, logout, passkey login, and the mobile
  layout.

The application never writes LocalWebAuthn grants, challenges, credentials, or sessions.
Those tables and their atomic updates belong to `SqliteLocalWebAuthnStore`.

## Test

Install Chromium for Playwright once if it is not already available:

```console
npx playwright install chromium
make demo-test
```

The regular `make check` also runs the demo's API-level bootstrap and authorization tests.

## Security Boundary

The example binds to `127.0.0.1`, uses HTTP only for localhost, and prints enrollment secrets
to the terminal. It is deliberately convenient for local review and is not a production
deployment template.

A production host must use an exact HTTPS origin, secure cookies, approved enrollment-link
delivery, rate limiting, audit persistence, and an explicit recovery policy. The demo keeps
those responsibilities visible rather than implying that a package can choose them safely
for every application.
