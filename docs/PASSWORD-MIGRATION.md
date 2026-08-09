# Migrating password auth to passkeys: interface-compatibility approaches

A planning document. It answers three questions and recommends a path; it implements nothing.

1. Is there a "standard" interface shared by the popular self-hosted (local password-checking)
   npm auth packages?
2. If so, can LocalWebAuthn implement that interface, or its significant parts, so migrating
   from password auth to passkeys is easier?
3. If so, can we ship migration examples where a working password app is moved over largely by
   swapping an import for a LocalWebAuthn equivalent?

Short answers: **there is no single formal standard, but there is a dominant de facto one**
(Passport's strategy + session contract), and it already has a WebAuthn shape. LocalWebAuthn
can implement the parts that do not depend on the shared-secret model, and that covers most of
an app's integration surface. But **"swap one import and it works" is only honest for the
session/authorization half.** The credential half — signup and login — cannot be a drop-in,
because passkeys change the authentication _protocol_, not just the library. The highest-value
deliverables are therefore a Passport strategy, a documented coexistence recipe, and worked
before/after examples — not a facade that pretends the protocols are the same.

## 1. The landscape of self-hosted local-password packages

Grouped by how an application integrates them, because that — not the hashing — is what a
migration has to preserve.

### a. Middleware + strategy frameworks

- **Passport** (`passport` + `passport-local`) is the de facto standard for pluggable auth in
  Node and by far the most-installed. Its integration surface is small and stable:
  - a **strategy**: `passport.use(new LocalStrategy((username, password, done) => …))`;
  - **route middleware**: `passport.authenticate('local', …)`;
  - a **session contract**: `serializeUser` / `deserializeUser`, and on the request
    `req.login()`, `req.logout()`, `req.isAuthenticated()`, `req.user`.
  - Fastify has parallel shapes (`@fastify/passport`, `@fastify/auth`).
- Crucially, **Passport already defines a WebAuthn strategy shape.** `passport-webauthn` /
  `passport-fido2-webauthn` (by Passport's own author) take a `verify(id, userHandle, cb)` and
  a `register(user, id, publicKey, cb)` — deliberately **not** `(username, password)`. That
  is direct evidence both that a Passport strategy is the idiomatic place to slot passkeys in,
  and that the credential step's _signature_ necessarily changes when you do.

### b. Model / ORM plugins

- **`passport-local-mongoose`** mixes password auth into a Mongoose schema: `User.register`,
  `User.authenticate()`, `setPassword`, `changePassword`. The "interface" is the plugin plus
  the methods it grafts onto the model.

### c. All-in-one frameworks (each with its own shape)

- **better-auth** — currently ascendant, self-hostable, email/password built in, plugin
  system. It already ships a first-class **passkey plugin** (`@better-auth/passkey`, SimpleWebAuthn
  under the hood). Migrating to passkeys _within_ better-auth is native; here LocalWebAuthn
  competes rather than shims.
- **Auth.js / NextAuth** (`@auth/core`, `next-auth`) — a `Credentials` provider does local
  password checking (`authorize(credentials)`), and there is an experimental WebAuthn/passkey
  provider. Heavily framework-shaped (session strategy, callbacks, `auth()`), Next.js-centric.
- **Lucia** — **deprecated (March 2025)**; the maintainer wound it down as a dependency and
  turned it into a "copy this single-file session code into your app" guide. Not a shim target,
  but the hand-rolled sessions it now teaches are a very common migration _source_.
- **SuperTokens**, **Supabase Auth (GoTrue)** — self-hostable but service-backed (a separate
  core process), not an embedded library; out of scope for an import-swap story.

### d. The hand-rolled majority

Most self-hosted password apps are not built on a framework at all: `bcrypt` / `bcryptjs` /
`argon2` for `hash` + `compare`, `express-session` (or a signed cookie) for the session, and a
`users.password_hash` column. There is no package interface here — just a recurring _pattern_.

## 2. Is there a standard interface?

No formal one. But three de facto contracts recur, and they are what a migration must speak:

1. **The Passport strategy contract** — `use()` / `authenticate()` / `serialize` / `deserialize`.
   The closest thing to a standard, already extended to WebAuthn.
2. **The Express session/identity contract** — `req.login`, `req.logout`, `req.isAuthenticated`,
   `req.user`. Independent of Passport; many apps rely on just this shape.
3. **The hashing primitive** — `compare(password, hash) → boolean`. Universal, and the one that
   _cannot_ survive the move (see §3).

The all-in-one frameworks each define their own fourth shape, but they are not shared across the
ecosystem and two of the three already have their own passkey path.

## 3. The impedance mismatch (the crux)

A password login is **one request carrying a shared secret** the server verifies locally:
`compare(password, hash) → bool`. A passkey login is a **challenge/response**: the server issues
a random challenge (request 1), the browser runs the WebAuthn ceremony against the origin, and
the server verifies a signature (request 2). There is no shared secret, no server-held verifier,
and the client does work the server cannot do for it. Enrollment differs too: a password is a
value the user types; a passkey is a credential created by a registration ceremony authorized by
an out-of-band grant.

Which integration surfaces survive an import swap, and which cannot:

| Surface                                        | Maps cleanly? | Why                                                                                  |
| ---------------------------------------------- | ------------- | ------------------------------------------------------------------------------------ |
| Session issuance / lookup (`req.user`, guards) | **Yes**       | LocalWebAuthn has sessions; `resolveSession` ≈ `deserializeUser`                     |
| Logout / revoke                                | **Yes**       | `revokeSession` ≈ `req.logout`; `revokeUserSessions` ≈ "sign out everywhere"         |
| `isAuthenticated` / route guard middleware     | **Yes**       | one `resolveSession` call                                                            |
| The user store lookup (`findUser`)             | **Yes**       | LocalWebAuthn's `getUser` provider; the host keeps its user table                    |
| Login **verb** (`authenticate('local')`)       | **Reshaped**  | becomes two endpoints (options → verify) + a browser ceremony; no password argument  |
| Signup / set password                          | **Reshaped**  | becomes an enrollment grant + a registration ceremony                                |
| `compare(password, hash)`                      | **No analog** | nothing to compare; verification needs a prior challenge and a client-side signature |
| Password reset / "forgot password" email       | **No analog** | no secret to reset; becomes re-enrollment, which is identity proofing (host policy)  |

The top four are ~80% of an app's auth-touching code and migrate almost for free. The bottom
four are the login form, the signup form, and the reset flow — and they change shape by
necessity. Any approach that claims otherwise is selling a facade over a different protocol.

## 4. Approaches

Ranked by value-to-honesty. Each notes how much "swap the import" it buys, the effort, and what
still has to change in the app.

### A. A Passport WebAuthn strategy — `@localwebauthn/passport` _(recommended, primary)_

Ship a Passport strategy that wraps LocalWebAuthn, mirroring the `passport-webauthn` shape. The
app keeps Passport, `serialize`/`deserialize`, `req.user`, guards, and its session store
untouched; it swaps `passport-local` for `@localwebauthn/passport` and replaces the single
`/login` handler with the options/verify pair (which the strategy and `@localwebauthn/browser`
drive).

- **Import-swap delivered:** the entire session/authorization surface, unchanged.
- **Still changes:** the login and signup _forms/endpoints_ (challenge/response), and the store
  now records a credential per user, not a hash. `passport-fido2-webauthn` already requires the
  same two-step + stored-challenge shape, so this is idiomatic, not novel.
- **Effort:** medium. A thin adapter over `authenticationOptions`/`verifyAuthentication` and
  `registrationOptions`/`verifyRegistration`, plus challenge storage via LocalWebAuthn's
  `challengeToken`. Risk: keeping the strategy's small surface honest about the two round trips.
- **Best for:** the large population of Passport-`local` apps.

### B. An Express session-compat shim — `req.login` / `req.user` / `isAuthenticated`

For apps on Passport's session shape but not its strategies (or hand-rolled around the same
verbs), a tiny middleware that populates `req.user` from a LocalWebAuthn session and offers
`req.login(session)` / `req.logout()` / `req.isAuthenticated()`.

- **Import-swap delivered:** the identity/guard surface.
- **Still changes:** login/signup, as always.
- **Effort:** low. Mostly a re-export of `resolveSession` + `revokeSession` in familiar clothing.
- **Caveat:** thin enough that a documented recipe (Approach F) may serve as well without a new
  package to version.

### C. A `passport-local-mongoose`-shaped model plugin

A Mongoose/Prisma plugin exposing `enrollPasskey`/`authenticatePasskey` where the old plugin
exposed `register`/`authenticate`.

- **Import-swap delivered:** the model-method names, roughly.
- **Reality:** the method _bodies_ change from sync-ish password ops to two-step ceremonies, so
  the shape survives but call sites still change. Narrow audience.
- **Effort:** medium, low payoff. Defer unless a concrete user asks.

### D. A hashing-primitive facade — `compare`-shaped shim

Re-export something named like `compare(password, hash)`.

- **Verdict: do not build.** There is no password and no local verify; a function with that
  signature could only lie, and would invite insecure "if (compare(...)) logIn()" call sites
  that skip the ceremony entirely. This is the one place a compatibility layer would be actively
  harmful. Call it out explicitly in docs so nobody attempts it.

### E. Framework-native integration (better-auth / Auth.js)

- **better-auth** already has `@better-auth/passkey`; there is nothing to shim. Positioning, not
  code: note in COMPARISON.md when better-auth's built-in passkeys are the better choice and when
  LocalWebAuthn's self-hosted, invitation-first model is.
- **Auth.js** — a first-party LocalWebAuthn _provider_ is conceivable, but Auth.js already has an
  experimental WebAuthn provider, so the marginal value is low and the framework coupling is high.
  Defer.

### F. Documentation-first migration recipes _(recommended, ship first)_

A migration cookbook plus worked before/after example apps (§6). The README already has a
["Coming From Password Authentication"](../README.org) mapping table (`password_hash` →
credential, `bcrypt.compare` → `verifyAuthentication`, reset email → `issueEnrollment`,
`req.session.userId` → `resolveSession`, …); this extends it into runnable diffs.

- **Import-swap delivered:** none — and that honesty is the point. It shows exactly what stays
  (most of the app) and what must change (the three forms).
- **Effort:** low, and it de-risks A and B by proving the shapes against real apps first.

## 5. Coexistence — the migration that actually happens

Real migrations are not big-bang import swaps; they are a **dual-run period**. This matters more
than any facade, and LocalWebAuthn suits it because it does **not** own the user table — it
attaches to the host's existing users via the `getUser` provider.

A phased path that keeps everyone logged in throughout:

1. **Add, don't replace.** Stand up LocalWebAuthn beside the existing password check, pointed at
   the same users. Legacy login still runs `bcrypt.compare`.
2. **Enroll opportunistically.** After a successful password login, offer "add a passkey"
   (`issueEnrollment` for that user → registration ceremony). Record a per-user
   `passkey_enrolled` flag in the host's own table.
3. **Prefer passkey.** Where a user has a credential, present the passkey flow first; fall back
   to password only if they have none.
4. **Retire the password.** Once coverage is high, stop accepting password login and drop the
   `password_hash` column. Recovery is now re-enrollment (identity proofing), per
   [README-DETAIL.org](../README-DETAIL.org).

The cookbook should lead with this, because "swap the import" describes step 4 of a process whose
first three steps are where the real work and the real safety live.

## 6. Proposed migration examples

Pick canonical "before" apps that dominate the installed base, and show the "after" as a diff:

1. **Passport-`local` + `express-session`** — the flagship. Before: `LocalStrategy` +
   `/login`. After: `@localwebauthn/passport` (Approach A) with `serialize`/`deserialize`/guards
   byte-identical; only the login/signup routes and the client change. This example _is_ the
   proof of Approach A.
2. **Hand-rolled `bcrypt` + `express-session`** — the silent majority (and what deprecated-Lucia
   apps now resemble). Before/after with the coexistence phases from §5, ending in a passkey-only
   app. No new package required — just LocalWebAuthn + the recipe.
3. _(optional)_ **Auth.js `Credentials`** — show the mapping to LocalWebAuthn's routes, framed as
   "here is the shape; a provider could formalize it," without committing to build the provider.

Each example should make the honest split visible: a small, mechanical session/guard diff, and a
deliberately larger, explained login/signup diff.

## 7. Recommendation

1. **Ship Approach F first** — the cookbook and examples 1 and 2. Lowest effort, immediately
   useful, and it validates the strategy's shape before any package is versioned.
2. **Then Approach A** — `@localwebauthn/passport`, once example 1 has proven the ergonomics.
   This is the credible "swap `passport-local` for us" story for the largest audience.
3. **Fold Approach B into A/F** rather than shipping a separate micro-package, unless demand
   appears.
4. **Explicitly rule out Approach D** in the docs.
5. **Treat E as positioning** in COMPARISON.md, not code.

Frame everything around §5 coexistence, and never let marketing shorten the promise to "just
change the import": the session layer is near-drop-in; the credential layer is a deliberate,
documented protocol change, and saying so plainly is what makes the migration trustworthy.

## 8. Facts to confirm before committing

- Current `passport` major and the exact `passport-webauthn` / `passport-fido2-webauthn` verify /
  register signatures to mirror (both existed and were maintained by Passport's author at review
  time; confirm the latest).
- Auth.js WebAuthn provider maturity, if example 3 is pursued.
- Whether any target app relies on Passport internals beyond the four surfaces in §3 (some use
  `req.authInfo`, custom `session` serialization, or `passport-local-mongoose` model methods).

## Sources

- [passport-fido2-webauthn (npm)](https://www.npmjs.com/package/passport-fido2-webauthn) and
  [jaredhanson/passport-webauthn](https://github.com/jaredhanson/passport-webauthn); the
  [Passport WebAuthn example app](https://github.com/passport/todos-express-webauthn).
- [Lucia "A fresh start" discussion](https://github.com/lucia-auth/lucia/discussions/1714) and
  ["Lucia Auth is Dead — What's Next"](https://www.wisp.blog/blog/lucia-auth-is-dead-whats-next-for-auth).
- [Better Auth passkey plugin](https://www.npmjs.com/package/@better-auth/passkey) and its
  [docs](https://better-auth.com/docs/plugins/passkey).
