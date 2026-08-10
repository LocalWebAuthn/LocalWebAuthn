# Migrating password authentication to passkeys

Status: planning document, reviewed 2026-08-09. It proposes product work but implements none of
it.

## Executive recommendation

The most fruitful path is **not a Passport strategy first**. It is a framework-neutral
**brownfield migration bridge** with two properties:

1. an existing application can keep its user table, authorization code, and current session
   cookie/session store while LocalWebAuthn verifies passkeys; and
2. its existing username/password page can offer passkeys through browser autofill
   (WebAuthn Conditional UI) without first asking whether an account has a passkey.

That foundation serves hand-rolled Express applications, Passport applications, applications
migrating away from Lucia, and framework-specific adapters. A Passport adapter can then be thin
and honest. Without the foundation, a Passport strategy cannot leave the application's session
store “untouched”: LocalWebAuthn currently creates a LocalWebAuthn session during every successful
registration and authentication. The result would be two session systems, or an adapter that
claims compatibility while silently replacing the application's session semantics.

The recommended order is:

1. Add a server-side **host-session handoff mode** and a browser-side **conditional sign-in
   mode**.
2. Publish two complete migration examples: hand-rolled `bcrypt` + `express-session`, then
   `passport-local` + `express-session`.
3. Add a server-side helper for enrollment authorized by a recent host authentication.
4. Only after the examples prove the contracts, consider `@localwebauthn/passport`.
5. Treat automatic passkey upgrades (Conditional Create) as a separate later feature. It needs a
   ceremony mode that can accept a response without user presence and must not treat that response
   as a fresh authentication event.

Do not build a `bcrypt.compare()`-shaped facade. A passkey ceremony cannot honestly or safely fit
that interface.

## 1. Corrections to the earlier proposal

The previous version found a useful ecosystem seam but overstated how much of it maps today.

### Passport is an adapter target, not the common substrate

There is no formal Node/JavaScript password-auth interface. Passport is a long-lived and important
integration contract, but claims such as “by far the most-installed” need dated package-usage data
and do not establish that it represents the hand-rolled majority. The recurring common substrate
is smaller:

- a host user ID and user lookup;
- a password-verification route;
- a host session/cookie created after authentication;
- route guards that resolve that host session; and
- account recovery and authenticator-management policy.

Passport exposes these through strategies, `req.logIn()`/`req.logout()`,
`serializeUser`/`deserializeUser`, and `req.user`. Many applications implement the same lifecycle
without Passport. LocalWebAuthn should first support the underlying lifecycle and then adapt it to
Passport.

Passport's official package catalog does contain `passport-fido2-webauthn`, which demonstrates
that WebAuthn belongs in a challenge/response strategy rather than in `passport-local`'s
`(username, password)` callback. It is not a drop-in design specification for LocalWebAuthn,
however: that strategy has its own challenge, credential-public-key, and registration callbacks.
LocalWebAuthn already owns those concerns. As of this review, Passport's catalog reports that
package as version 0.1.0, published in 2022; audit its behavior and maintenance status before using
it as an interoperability baseline.

### Session compatibility is not currently clean

The current implementation atomically creates a LocalWebAuthn session in both
[`verifyRegistration`](../packages/server/src/service.ts) and `verifyAuthentication`. Its store
contract likewise couples credential completion/counter advancement to session creation. Therefore:

- `resolveSession` can underpin a new guard, but is not equivalent to an existing application's
  `deserializeUser` unless that application adopts LocalWebAuthn's session cookie and lifetime;
- `revokeSession` is not equivalent to `req.logout()` when the host still has a different session;
- `req.logIn()` takes a user/principal and asks Passport to establish a login; it does not take a
  LocalWebAuthn session token; and
- “keep the Passport session store untouched” requires a verified-principal handoff that the core
  does not yet provide.

The distinction is a product decision, not adapter glue. Section 4 specifies the missing mode.

### A passkey does have a server-side verifier

A password request carries a reusable shared secret and the server generally stores a salted
password hash. A WebAuthn relying party stores the credential's **public key**, which is a verifier,
but not a reusable secret with which an attacker can impersonate the user. The relevant security
claim is “no reusable shared secret or private signing key is stored by the server,” not “no
server-held verifier.”

### The claimed “80%” compatibility was unsupported

Session and guard code may be a large part of one application and a small part of another. Data
migration, enrollment authorization, recovery, account settings, support processes, and rollout
instrumentation are often more costly than route guards. The examples should measure changed call
sites and operational work instead of assigning a universal percentage.

### A password fallback remains an account-level downgrade

During dual-run, accepting either a password or a passkey means an attacker can choose the weaker
accepted route. Passkeys improve the passkey login path immediately, but the account does not gain
passkey-only phishing resistance while password login or a comparably weak recovery route remains
enabled. Product copy and migration metrics must not count “has one passkey” as “passwordless” or
“phishing-resistant.”

## 2. Ecosystem map and target selection

Group targets by the state LocalWebAuthn must coexist with, rather than by their hashing package.

### Hand-rolled Node applications — primary target

The recurring shape is `bcrypt`/`bcryptjs`/`argon2`, a user table with `password_hash`, and
`express-session` or a signed session cookie. There is no strategy contract to implement. These
applications benefit directly from a host-session handoff, a data-migration recipe, ready-made
route handlers, and a conditional-UI client example.

### Passport applications — primary example, secondary package

These applications add a stable middleware vocabulary. Once the core can verify a credential
without issuing its own session, an adapter can call the host's existing login function and leave
serialization, authorization guards, and session storage in place.

### Lucia v3 applications — documentation target

Lucia v3 is deprecated, and its official migration guide now teaches applications to implement
their own sessions. That makes these applications another instance of the hand-rolled-session
case, not a reason to build a Lucia adapter.

### All-in-one auth frameworks — positioning targets

- Better Auth has a maintained passkey plugin powered by SimpleWebAuthn. An application already
  committed to Better Auth will normally have less work using its native plugin.
- Auth.js is highly framework- and session-shaped. Verify the exact target version and current
  WebAuthn support before proposing an adapter; do not base a roadmap on an “experimental
  provider” claim without a current official API reference.
- Service-backed systems such as Supabase Auth and SuperTokens have a different ownership and
  deployment model. Migration from them is an identity-provider migration, not an npm import
  swap.

LocalWebAuthn's differentiation is the self-hosted, passkey-only lifecycle and explicit enrollment
and recovery model. It should not reproduce every framework's schema and session abstractions.

## 3. What can and cannot be compatible

| Existing surface                         | Compatibility goal                                                                    | Current status                                                                     |
| ---------------------------------------- | ------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Host user table and stable user ID       | Keep it; add a stable WebAuthn user handle                                            | Supported through `getUser`, but schema/backfill guidance is missing               |
| Existing session/cookie and route guards | Host creates the same session after passkey verification                              | **Not supported directly**; verification always creates a LocalWebAuthn session    |
| LocalWebAuthn-owned session              | Adopt `resolveSession`/revocation and replace host session behavior                   | Supported; this is a separate migration choice                                     |
| Password login page                      | Add passkey autofill alongside the existing fields                                    | Server ceremony is compatible; browser client lacks Conditional UI mode            |
| Password login route                     | Keep for a controlled dual-run period                                                 | Host responsibility                                                                |
| `compare(password, hash)`                | No compatibility goal                                                                 | No honest analog                                                                   |
| Password-authorized passkey enrollment   | Host proves a recent password auth; LocalWebAuthn binds a new credential to that user | Possible with grant primitives, but awkward and not packaged as a server-side flow |
| Password reset/recovery                  | Replace with host-defined re-proofing and re-enrollment                               | Deliberately host policy; must not be presented as a mechanical mapping            |
| Credential management                    | Use LocalWebAuthn list/revoke/ancestry operations                                     | Supported; needs migration UI examples                                             |

There are two valid session architectures and the docs must name them explicitly:

1. **LocalWebAuthn-owned session:** replace the old session system. This gives the host
   LocalWebAuthn's expiry and credential-revocation semantics, but is not a session-compatible
   migration.
2. **Host-owned session:** LocalWebAuthn verifies and commits credential state, then returns an
   authenticated principal to trusted server code; the host rotates and creates its usual session.
   This is the lowest-disruption brownfield path.

Trying to run both indefinitely makes logout, global revocation, freshness, and incident response
ambiguous. A dual-session deployment should be a deliberate temporary architecture with an
explicit source of truth.

## 4. P0: host-session handoff mode

### Required behavior

Add a server-configured verification mode that completes WebAuthn verification and the credential
state transition without creating a LocalWebAuthn session. The mode must be selected by trusted
server configuration or a server-only call, never by a field copied from the browser request.

A possible result shape is:

```ts
type HostAuthenticationResult = {
  verified: true;
  user: PublicUser;
  credentialId: string;
  credentialKind: string | null;
  authenticatedAt: number;
  session: null;
};
```

The host's verification route consumes this result and, before returning success to the browser:

1. regenerates the anonymous/pre-authentication session ID to prevent session fixation;
2. stores the same stable host user ID and authorization data that password login stores;
3. records authentication context such as `method: 'passkey'`, `authenticatedAt`, and optionally
   `credentialId`/credential kind for step-up and audit decisions; and
4. sends only a generic success response to the browser.

Do not make the browser present `userId` after verification and do not accept a browser-selected
principal. The verified credential and user handle determine the user.

### Store/API implementation options

**Option A — recommended: allow sessionless atomic completion.** Permit `session: null` in
`completeAuthentication` and `completeRegistration`. The same transaction still consumes the
authorization, advances the signature counter with compare-and-swap, and commits credential
state; it merely omits the session insert and `session.created` event. Return a discriminated
result so callers cannot accidentally treat a missing session token as a LocalWebAuthn session.

This is the most direct composition model. It changes every built-in store and the public custom
store contract, so it needs contract tests and migration notes.

**Option B — separate completion methods.** Add `completeAuthenticationWithoutSession` and
`completeRegistrationWithoutSession`. This makes the security distinction explicit but expands
the custom-store interface and risks drift between two implementations of the same counter and
authorization invariants.

**Option C — one-time session exchange.** Create a short-lived LocalWebAuthn session or handoff
token and atomically exchange it for a host login. This can separate the LocalWebAuthn routes from
the host session endpoint, but adds another bearer secret, replay state, failure modes, and
revocation semantics. Use it only where the verifying component cannot directly invoke the host's
session-establishment callback. The token must be audience-bound, single-use, short-lived, stored
hashed, and exchanged server-to-server or through a same-origin HttpOnly cookie.

Do not implement sessionless completion by creating a normal LocalWebAuthn session and immediately
revoking it. That leaves misleading events and transient state, adds failure windows, and obscures
which session system is authoritative.

### Registration and authentication must be independently configurable

A host may want registration to leave an already-authenticated password session in place while
authentication creates a new host session. Conversely, an application adopting LocalWebAuthn
sessions may want today's behavior. Make the choice explicit for each ceremony and test all
supported combinations.

## 5. P0: Conditional UI on the existing password page

Conditional UI is the highest-leverage browser integration. It lets a discoverable passkey appear
in the browser's autofill UI on the existing username/password form. Users without a passkey keep
using the form, and the server does not need to answer an account-enumerating “does this username
have a passkey?” query.

LocalWebAuthn is already well-shaped for it:

- registration requires discoverable credentials (`residentKey: 'required'`);
- authentication is usernameless and omits `allowCredentials`; and
- user verification is required.

Extend [`LocalWebAuthnBrowser`](../packages/browser/src/index.ts) with either a clearly named
`startConditionalSignIn()` or a discriminated `signIn({ mode: 'conditional' })`. Internally, the
current SimpleWebAuthn API uses:

```ts
startAuthentication({ optionsJSON, useBrowserAutofill: true });
```

The example login page should:

- use `autocomplete="username webauthn"` (with `webauthn` last);
- start the conditional request early after the login page loads;
- cancel the pending ceremony on client-side navigation and coordinate it with an explicit
  passkey button or password submission;
- treat cancellation as normal, not as a login error;
- fetch a fresh options/challenge pair when the stored challenge has expired; and
- preserve a normal password path during the dual-run cohort.

SimpleWebAuthn coordinates overlapping ceremonies and exposes `WebAuthnAbortService` for manual
cancellation. Wrap those semantics rather than adding an independent abort mechanism. Add tests
for two starts, password submission while the request is pending, navigation/unmount, challenge
expiry, unsupported browsers, and conditional success through the host-session callback.

Do not decide whether to render password fallback based on an unauthenticated credential-count
lookup. A generic login page can always render the temporary fallback during dual-run; policy can
remove it by cohort or authenticated account state later.

## 6. P1: password-authorized enrollment

The host, not LocalWebAuthn, knows whether a password was just verified. LocalWebAuthn should offer
a safe way for trusted server code to turn that fact into a tightly scoped registration
authorization without making developers send themselves an enrollment URL.

One possible helper is `beginHostAuthorizedEnrollment(userId, options)`, implemented using the
same grant and enrollment-session invariants as `issueEnrollment` + `exchangeEnrollment`, but
returning an enrollment-session token directly to trusted server code (normally placed in a
same-origin HttpOnly cookie). The exact name is less important than these properties:

- the host passes a stable user ID obtained from its authenticated server session, never from an
  untrusted request body;
- the authorization is short-lived, single-use, and purpose-bound to registration;
- creating it supersedes or otherwise safely handles older pending grants;
- the credential retains its enrollment provenance and audit events;
- CSRF and Origin checks protect the route that begins enrollment;
- no bearer token is placed in a URL, log, analytics event, or browser-readable storage; and
- host policy can record who/what approved the enrollment.

For the first passkey on a password account, require a **recent password reauthentication**, not
merely an old logged-in session. For higher-risk accounts, also require the account's existing MFA
or an administrative/recovery proof. Adding an authenticator is a sensitive account change: notify
the user out of band, log it, rate-limit it, and consider a cooling-off period before the new
credential can remove other authenticators or disable recovery.

A compromised password can be used to bind an attacker's passkey. That is unavoidable if the
password is accepted as the bootstrap proof, but it should be explicit in the threat model and
mitigated rather than hidden behind “opportunistic enrollment.”

## 7. P2: automatic passkey upgrades (Conditional Create)

WebAuthn Level 3 and current SimpleWebAuthn browser APIs support an opportunistic auto-registration
mode after a successful password-manager login:

```ts
startRegistration({ optionsJSON, useAutoRegister: true });
```

This could materially improve adoption, but should follow the explicit enrollment flow. The
registration response can have its User Presence bit unset. LocalWebAuthn currently verifies
registration using the normal user-presence expectation and then creates an authenticated session,
so simply exposing `useAutoRegister` would be wrong.

Safe support requires a server-created, challenge-bound registration mode such as
`'explicit' | 'auto-upgrade'`:

- only the `auto-upgrade` mode may verify with `requireUserPresence: false`;
- the browser cannot choose or upgrade the mode;
- the host must have independently completed a successful password authentication immediately
  before it requests auto-upgrade options;
- successful auto-upgrade stores the credential but **does not mint, refresh, or elevate a
  session** and is not recorded as fresh passkey authentication;
- a later passkey authentication must succeed before the host labels the account passkey-ready or
  permits password retirement; and
- failure is opportunistic and must leave the password login successful.

Feature-detect support, collect success/failure metrics without credential material, and retain an
explicit “Add a passkey” path. Browser support and behavior vary; do not make automatic upgrade a
prerequisite for the migration product.

## 8. P2: Passport adapter after the core is proven

Build the Passport example before publishing a package. A useful
`@localwebauthn/passport` adapter should consume host-session mode rather than reimplement WebAuthn,
challenge storage, or credential persistence.

The flagship before/after should keep these host behaviors unchanged:

- `serializeUser` and `deserializeUser`;
- the session store and cookie policy;
- `req.user`, `req.isAuthenticated()`, and downstream authorization guards; and
- logout/global host-session behavior.

The options and verification routes necessarily change, as does the browser page. After successful
LocalWebAuthn verification, the adapter calls Passport's login mechanism with the verified host
user and ensures the session ID is regenerated. It must define how Passport errors, redirects,
`failureFlash`, `req.authInfo`, custom callbacks, and stateless `session: false` mode behave.

Do not mirror `passport-fido2-webauthn`'s public-key storage callback. LocalWebAuthn's value is that
it owns credential/challenge lifecycle and its atomic invariants. A Passport adapter should adapt
the result, not fork the verifier.

Package the adapter only if the worked example shows enough repeated, security-sensitive glue to
justify another supported API. Otherwise keep it as an audited recipe.

## 9. User-data migration

LocalWebAuthn deliberately leaves the host user table in place. Each existing user nevertheless
needs `webAuthnUserHandle`: a stable, unique, cryptographically random 32-byte value.

Recommended schema migration:

1. Add a nullable binary or base64url-text column with a uniqueness constraint.
2. Backfill with `createUserHandle()` in bounded batches, or lazily allocate inside a transaction
   with collision retry.
3. Make it non-null before enabling enrollment for the whole population.
4. Treat it as immutable once any credential exists. Never derive it from an email address,
   username, or sequential database ID.
5. Return it through `getUser` without exposing it as a user-visible account identifier.

Keep LocalWebAuthn's credential tables separate from `password_hash`. Do not copy password hashes
into LocalWebAuthn storage.

Avoid an independently writable `passkey_enrolled` boolean. It can drift from credential
revocation and deletion. Prefer a server-side credential/readiness query, or maintain denormalized
state from durable LocalWebAuthn events with reconciliation. Never expose that state through an
unauthenticated username lookup.

If usernames or display names change, the WebAuthn user handle remains stable. Consider the Level
3 credential signaling APIs (`signalCurrentUserDetails`, `signalAllAcceptedCredentials`, and
`signalUnknownCredential`) as later account-maintenance enhancements; feature-detect them and do
not make correctness depend on them.

## 10. Coexistence and password retirement

Use explicit states rather than a single enrolled flag. A host might track:

```text
password-only -> hybrid -> passkey-preferred -> passkey-only
                         \-> recovery-pending
```

Suggested gates:

1. **Password-only:** normal password security, throttling, reset, and compromise controls remain.
2. **Hybrid:** a credential has been registered, but password remains accepted. Notify the user
   and encourage a real passkey sign-in.
3. **Passkey-preferred:** at least one later passkey authentication has succeeded. Offer
   conditional passkey UI first while retaining the controlled fallback.
4. **Passkey-only:** disable password only after the application's recovery policy is satisfied.
   Depending on the population, that may mean another credential, a verified synced-passkey
   recovery expectation, an administratively operated re-proofing path, or some combination.
5. **Recovery-pending:** prevent new recovery proof from immediately deleting established
   credentials or disabling notifications; apply the host's recovery waiting/veto policy.

Do not delete `password_hash` immediately when password login is disabled. First stop accepting it,
observe the rollback window, verify support/recovery readiness, and then erase hashes under a
documented retention process. Keep password rate limiting and reset defenses until the route is
actually disabled. Re-enabling password during rollback must be an explicit security decision, not
an automatic fallback.

Passkeys are authenticators, not automatically “MFA.” Synced passkeys can satisfy strong assurance
requirements in appropriate deployments, but are exportable by design and have different assurance
properties from device-bound authenticators. Make assurance and recovery policy population-specific.

## 11. Worked examples to ship

### Example 1 — hand-rolled Express (ship first)

Before: `bcrypt.compare`, `express-session`, a password form, and an authenticated dashboard.

After, in successive commits:

1. add/backfill `webAuthnUserHandle` and install LocalWebAuthn tables;
2. add recent-password-authorized explicit enrollment;
3. add conditional passkey sign-in to the unchanged password page;
4. establish the existing Express session from host-session verification and regenerate its ID;
5. add credential management, notifications, audit, and recovery states;
6. roll out by cohort with password fallback; and
7. disable, observe, and finally erase password hashes.

This example tests the real common contract without hiding it behind a framework.

### Example 2 — Passport Local

Start from a conventional `LocalStrategy` application. Preserve serialization, session store,
guards, and downstream authorization. Show exactly which login/enrollment routes and browser code
change. First implement it using the core result callback; extract an adapter only after repeated
glue is visible.

### Example 3 — existing LocalWebAuthn sessions (optional contrast)

Show the alternative where the application intentionally replaces its session system with
LocalWebAuthn's. This prevents readers from confusing “preserve host sessions” with the only valid
architecture and documents the operational differences in logout, revocation, and expiry.

Do not prioritize an Auth.js example until its target-version API is confirmed, or ORM-shaped
plugins whose ceremony call sites still have to change.

## 12. Rollout, observability, and acceptance criteria

Roll out by tenant or user cohort with a kill switch that stops new enrollment/conditional UI
without corrupting existing credentials. Measure:

- enrollment offered, started, completed, and later proven by authentication;
- conditional UI availability, selection, cancellation, and verification success;
- passkey login success, password fallback, and recovery/support rates;
- time in each migration state; and
- password-disabled and password-hash-erased populations as separate numbers.

Never log raw challenges, enrollment/session/handoff tokens, WebAuthn responses, session cookies,
or password material. Bound metric labels; credential IDs and user IDs belong in protected audit
records, not general telemetry.

Minimum acceptance tests for the migration foundation:

- host-session verification advances the credential counter atomically and creates **no**
  LocalWebAuthn session or `session.created` event;
- the host session ID changes at successful authentication and downstream authorization sees the
  same user shape as password login;
- a client-supplied user ID or session-mode flag cannot change the verified principal or mode;
- revoked credentials, inactive users, wrong user handles, replayed/expired challenges, and lost
  counter compare-and-swap all fail before host login;
- a stale host session cannot authorize first-passkey enrollment where recent password proof is
  required;
- enrollment start and credential-management routes enforce CSRF/Origin policy and generic error
  behavior;
- concurrent or replayed enrollment cannot register two credentials from one authorization;
- conditional UI coexists with password submit and explicit passkey login without two active
  ceremonies or user-visible cancellation errors;
- auto-upgrade mode, if implemented, cannot mint/elevate a session and cannot be selected by the
  browser; and
- disabling password does not strand accounts outside the declared recovery policy.

Run all examples and package tests through the repository's Nix flake so their Node/package-manager
versions match the supported development environment.

## 13. Delivery plan

### Milestone 1 — prove the seam

- Add sessionless completion to server types, service, built-in stores, events, and tests.
- Add a host session-establishment callback example with explicit fixation protection.
- Add Conditional UI and cancellation handling to the browser package.
- Build the hand-rolled Express dual-run example.

### Milestone 2 — make enrollment operable

- Add the host-authorized enrollment helper.
- Document recent-auth, CSRF, notifications, recovery, readiness states, and password retirement.
- Add migration telemetry hooks and the Passport before/after example.

### Milestone 3 — extract only proven adapters

- Decide from the examples whether a Passport package removes meaningful repeated code.
- Consider explicit auto-upgrade mode with its no-user-presence/no-session invariants.
- Consider WebAuthn credential signaling for renamed/deleted accounts.

This ordering produces useful migration guidance after Milestone 1 even if no framework adapter is
ever published.

## Sources

Primary specifications and project documentation checked for this review:

- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/) — conditional mediation,
  conditional creation, discoverable credentials, and credential signaling.
- [SimpleWebAuthn browser documentation](https://simplewebauthn.dev/docs/packages/browser/) —
  `useBrowserAutofill`, `useAutoRegister`, cancellation, and current client API shapes.
- [Passport's `passport-fido2-webauthn` catalog entry](https://www.passportjs.org/packages/passport-fido2-webauthn/)
  — the existing Passport strategy/callback shape and dated release metadata.
- [Better Auth passkey plugin documentation](https://better-auth.com/docs/plugins/passkey) — its
  native passkey support.
- [Lucia's official v3 migration page](https://lucia-auth.com/lucia-v3/migrate) — deprecation and
  migration to application-owned sessions.
- [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html) — phishing resistance and
  authenticator-assurance considerations.
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
  and [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
  — reauthentication for sensitive changes and session-ID regeneration after authentication.
- [FIDO Alliance, Displace Password + SMS OTP Authentication with Passkeys](https://fidoalliance.org/wp-content/uploads/2024/07/FIDO_EDWG_Displace-password-OTP-authentication-with-passkeys-FINAL_Approved.docx.pdf)
  — staged deployment and adoption monitoring considerations.
