# Hono + Node starter

Minimal **passkey-only** HTTP surface using `@localwebauthn/server` helpers:

- `authCookieNames` / `cookieAttributes` / `isExactOrigin`
- `signupPhase` for host-owned user state
- SQLite store + the six browser protocol routes

No UI. Pair with `@localwebauthn/browser` or the lifecycle [demo](../demo).

## Run

From the repo root (workspace):

```console
nix develop
npm install
npm run start --workspace @localwebauthn/starter-hono
```

Prints a bootstrap enrollment URL. Exchange and register with any client that
speaks the default `/api/auth/*` protocol (see main README).

## Layout

| File                 | Role                                         |
| -------------------- | -------------------------------------------- |
| `src/db.ts`          | App `users` table + LocalWebAuthn migration  |
| `src/auth-routes.ts` | Cookie + origin adapter (copy into your app) |
| `src/server.ts`      | Bootstrap admin, health, session probe       |

For a full admin UI (invite, re-enroll, passkey list), use `examples/demo`.
