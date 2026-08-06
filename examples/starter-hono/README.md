# Hono + Node starter

Minimal **passkey-only** HTTP surface using `@localwebauthn/server` helpers:

- `authCookieNames` / `cookieAttributes` / `isExactOrigin`
- `signupPhase` for host-owned user state
- SQLite store + the six browser protocol routes

No UI. Pair with `@localwebauthn/browser` or the lifecycle [demo](../demo).

## Run

From the repo root (workspace), prefer the flake shell:

```console
nix develop
make install          # if needed
make starter-hono
# outside the shell:
make nix-starter-hono
```

Equivalent npm: `npm run start --workspace @localwebauthn/starter-hono`.

Prints a bootstrap enrollment URL. Exchange and register with any client that
speaks the default `/api/auth/*` protocol (see main README).

Worth knowing before you poke at it:

- **POSTs need an `Origin` header.** Every state-changing route enforces an
  exact-origin check, so curl must say
  `-H 'Origin: http://localhost:4180'` or you get `invalid_origin`.
- **Restarting reissues the bootstrap link.** With zero credentials, each start
  revokes the previous grant and prints a fresh URL; stale links die.
- **`/api/invite` is authorization-free by design** — any signed-in session may
  invite, and there is no rate limit. Add your role model before deploying.
- **Behind a TLS proxy, set `STARTER_PUBLIC_ORIGIN=https://…`.** The server
  binds `127.0.0.1` and derives `Secure` / `__Host-` cookies from the public
  origin, not the local socket — exactly what a reverse-proxied deployment
  needs. Non-loopback `http://` origins are rejected at startup.

## Layout

| File                 | Role                                         |
| -------------------- | -------------------------------------------- |
| `src/db.ts`          | App `users` table + LocalWebAuthn migration  |
| `src/auth-routes.ts` | Cookie + origin adapter (copy into your app) |
| `src/server.ts`      | Bootstrap admin, health, session probe       |

For a full admin UI (invite, re-enroll, passkey list), use `examples/demo`.
