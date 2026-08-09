# LocalWebAuthn vs the Passkey Ecosystem

How LocalWebAuthn fits among existing JavaScript / TypeScript options for
passkey (WebAuthn) authentication, what those projects actually provide, and
where this one stands relative to current practice.

This is a product and architecture comparison, not a cryptographic audit of
peers. Capabilities change; treat version claims as approximate as of mid-2026
and verify against each project's docs before choosing.

## Target audience

### The short version

LocalWebAuthn is for teams who want to **stop running a password system** and
**authenticate only with passkeys**, while keeping authentication **inside their
own application** — so that a working login depends on the user (browser +
authenticator), the target service, and whatever terminates HTTPS for that
service (the app's own certificates, or a reverse proxy / CDN such as
Cloudflare). It is **not** for teams whose auth plan still requires a hosted
identity provider, social login, or email/SMS as a standing authentication or
reset channel.

### What that framing does and does not mean

Four parts of it are easy to over-read.

**"Replace passwords" means replacing the shared-secret pipeline, not the word.**
A password field commits you to hashing, policy, reset tokens, stuffing
defenses, and usually a second factor; passkeys remove the reusable server-side
secret entirely. But magic links and OTP recovery rebuild the same weak front
door under a different name. Swapping a password box for an emailed code is not
the change this package is about.

**"No third parties" is about the runtime trust model, not the dependency
tree.** Completing a ceremony needs no Auth0, Clerk, Hanko Cloud, OIDC redirect,
or mail provider. Three things it does not claim: npm still supplies ceremony
code (`@simplewebauthn/*`) and optional database drivers; TLS may be terminated
by a reverse proxy or CDN, which is transport rather than an identity provider;
and a user may sync passkeys through Apple, Google, or a password manager, which
is _their_ authenticator choice — LocalWebAuthn never sees the private key and
does not treat that vendor as the application's IdP.

**Passwords being unfixable does not make recovery disappear.** You cannot tune
bcrypt out of phishing and credential stuffing, so the front door genuinely
improves. Recovery, though, becomes identity proofing plus re-enrollment rather
than "email me a new secret." An organization that cannot operate that bar
should choose a multi-method framework or IdP instead — see
[Designing Recovery](../README-DETAIL.org).

**"Anyone who wants passkeys" is too broad, but the limit is not "self-serve".**
The fit is populations you enroll deliberately, on passkey-capable clients.
"Deliberately" means the enrollment capability is explicit, single-use, and
bound to one user — not that a human administrator has to issue it. An automated
signup that proves control of a channel and then calls `issueEnrollment()` fits
exactly as well as an administrator clicking a button; see
[Automated self-serve enrollment](#automated-self-serve-enrollment). What does
not fit is treating a mailbox as a standing credential.

### Who is in the audience

- TypeScript applications that **own the user table** and HTTP surface.
- Products that can require **passkey-capable** browsers/devices (or accept
  that unsupported clients are out of scope).
- Deployments that want auth data in **their** SQLite, PostgreSQL, or D1 — not
  in a vendor's user directory.
- Teams willing to design **enrollment delivery** and **recovery proofing** as
  first-class policy (see
  [Designing Recovery](../README-DETAIL.org)).
- Operators who care that the authentication path is **small enough to read**
  (~4,000 lines of lifecycle code on top of SimpleWebAuthn).

### Who is not

- Teams that need **OAuth/OIDC, SAML, or enterprise directory** integration as
  the primary login.
- Applications where **email or SMS is a standing way in** — "click the link we
  emailed" available at any time, to any account, forever. That makes every
  account only as strong as its mailbox, which is the thing passkeys were
  supposed to fix. Using those channels _once_ to bootstrap a passkey is a
  different matter and is well supported.
- Applications that must keep **passwords or magic links** as permanent
  fallbacks for the same accounts.
- Organizations that will not run or review **their own** auth path and prefer
  a mature hosted IdP.
- Populations whose devices or accessibility needs make **mandatory passkeys**
  inappropriate.

### Automated self-serve enrollment

Nothing about LocalWebAuthn requires a human in the loop. `issueEnrollment()`
takes an optional approver, not a mandatory one, and the grant it returns is
single-use, expiring, hashed at rest, and bound to exactly one user — which is
precisely the primitive an automated signup wants.

A self-serve flow that proves control of two independent channels before
enrolling is a good fit:

1. The visitor submits an email address and a phone number.
2. Your application verifies both — a DKIM-signed message with a one-time code
   or link, and an SMS or voice code — and only then creates the user row.
3. Call `issueEnrollment(userId)` and deliver the link over the channel you just
   verified.
4. The browser exchanges it and creates a passkey.
5. **From then on, sign-in is passkey-only.** Email and SMS are not login
   methods; they were bootstrap proofing.

Recovery re-runs the same proof, then `revokeUserAuthentication()` followed by a
fresh `issueEnrollment()`.

The caveats are about your proofing, not about the package:

- **Enrollment is only as strong as the weakest channel you accept.** One
  channel means account security equals mailbox security. Two channels are much
  stronger — provided they are genuinely independent. If the phone number is the
  recovery method for the email account, they collapse into one factor.
- **A phone number is weaker than it feels.** Numbers get ported and SIM swaps
  are cheap and targeted. Treat "controls the number today" as evidence, not
  proof.
- **Self-serve means abuse handling is yours.** Rate limiting, disposable-domain
  policy, and bot defense are host concerns in any design; this package does not
  provide them.
- **It costs you the clean runtime story at enrollment time.** Login still needs
  only the user, your service, and HTTPS — but onboarding now depends on a mail
  provider and an SMS provider. That is a one-time dependency rather than a
  standing one, and worth stating plainly to yourself when you claim "no third
  parties."

[Designing Recovery](../README-DETAIL.org) covers the same two-channel
pattern in more depth, including why the proofing bar has to be high.

### What "up" means for availability

For a user to sign in, these must work:

1. The user's device and authenticator (and, if they use a synced passkey, that
   sync provider — chosen by the user, not by your app's auth architecture).
2. Your relying-party application and its database.
3. HTTPS to that application (self-terminated or via a reverse proxy / CDN).

These need **not** work for login itself: a third-party IdP control plane, an
email or SMS provider, or a separate auth microservice (unless you deliberately
deploy one). Enrollment _delivery_ may still use email or chat as a
**one-time human channel**; that is not the same as "email is the authenticator."

---

## The problem looks simple until it is not

A passkey login feels minimal from the outside: the browser holds a private key,
the site stores a public key, HTTPS binds the origin. In practice a relying party
must still implement a stack of decisions that WebAuthn itself does not specify:

| Layer                  | What it is                                                      | Who usually owns it              |
| ---------------------- | --------------------------------------------------------------- | -------------------------------- |
| Ceremony               | Challenge generation, attestation/assertion parse and verify    | WebAuthn library                 |
| Credential store       | Public keys, counters, transports, revocation                   | Application or auth framework    |
| Challenge store        | Short-lived, single-use, origin-bound challenges                | Application or auth framework    |
| Bootstrap / enrollment | How the _first_ passkey is bound to a real person               | Application policy               |
| Sessions               | Opaque tokens, idle/absolute expiry, logout, credential binding | Application or auth framework    |
| Recovery               | Replacing lost authenticators without weakening the front door  | Application policy               |
| HTTP surface           | Cookies, CSRF/origin checks, rate limits, routes                | Application or framework adapter |

Most "passkey libraries" stop at the first row. Most "auth frameworks" cover
several rows but still assume passwords, email magic links, OAuth, or a separate
auth service. LocalWebAuthn deliberately occupies the middle: a **passkey-only
lifecycle library** that sits on top of a ceremony library and under your app's
users, HTTP, and identity-proofing policy.

**Dependencies vs identity providers.** LocalWebAuthn is not "zero npm
packages": ceremony crypto is delegated to
[`@simplewebauthn/server`](https://simplewebauthn.dev/) and
[`@simplewebauthn/browser`](https://simplewebauthn.dev/). The intentional
non-dependency is an **external identity provider** — no Auth0/Clerk/Hanko Cloud
account, no OIDC redirect, no required email/SMS _authentication_ pipeline.
See [Target audience](#target-audience) for how HTTPS terminators and user-chosen
passkey sync fit that model.

## Map of the landscape

```text
                    Hosted IdPs / commercial passkey APIs
                    (Auth0, Clerk, Corbado, Passage, ...)
                                      |
         Self-hosted auth *services*  |  (Hanko, SuperTokens core, Keycloak, ...)
                                      |
         Full app auth *frameworks*   |  (Better Auth, Auth.js/NextAuth, ...)
                                      |
         Lifecycle *libraries*        |  (LocalWebAuthn, devise-passkeys-style wrappers)
                                      |
         Ceremony *libraries*         |  (SimpleWebAuthn, @passwordless-id/webauthn)
                                      |
                              WebAuthn / FIDO2 platform APIs
```

[passkeys.dev](https://passkeys.dev/docs/tools-libraries/libraries/) lists
TypeScript ceremony libraries as **SimpleWebAuthn** and
**@passwordless-id/webauthn**. Everything above that layer is either application
code, a framework plugin, or a multi-tenant auth product.

---

## Ceremony libraries (primitives)

These make WebAuthn usable. They do **not** own users, enrollment grants,
sessions, or recovery.

### SimpleWebAuthn

- **What it is:** The de facto TypeScript WebAuthn toolkit
  (`@simplewebauthn/server` + `@simplewebauthn/browser`). Full-stack coverage,
  strong docs, widely used as the engine under other products (including Better
  Auth's passkey plugin and Auth.js's experimental provider).
- **Approach:** Export `generate*Options` / `verify*Response`. You persist
  challenges and credentials yourself. Multi-origin / multi-RP-ID support is
  first-class on the server package.
- **Strengths:** Spec fidelity, maintenance, ecosystem mindshare, browser +
  server pair, conformance posture.
- **Gaps vs LocalWebAuthn:** No invitation enrollment, no hashed bearer tokens,
  no session model, no store adapters, no audit events, no recovery guidance.
  Every production app rebuilds that layer.
- **Relation:** LocalWebAuthn **uses** SimpleWebAuthn as its default
  `CeremonyProvider`. It does not reimplement attestation/assertion crypto.

### @passwordless-id/webauthn

- **What it is:** Minimal, dependency-free, opinionated client + server helpers
  around WebAuthn. Documented for Node 19+, Cloudflare Workers, and other
  WebCrypto environments. Associated with the free public IdP
  [Passwordless.ID](https://passwordless.id) but the library is usable standalone.
- **Approach:** High-level `client.register` / `client.authenticate` and
  `server.verifyRegistration` / `server.verifyAuthentication`. Defaults favor
  convenience (e.g. user verification `preferred` in v2).
- **Strengths:** Very small surface, no heavy dependency tree, plain demos,
  good for learning and thin stacks.
- **Gaps:** Still ceremony-only. Persistence, sessions, multi-device enrollment
  policy, and bootstrap are your problem. Defaults are less strict than
  LocalWebAuthn's `userVerification: 'required'` / discoverable-credential
  posture.
- **Relation:** Alternative ceremony backend. LocalWebAuthn could theoretically
  wrap a different provider via `ceremonies`, but ships SimpleWebAuthn.

**Takeaway:** If you only need "call WebAuthn correctly," these are the state of
the art. If you need "ship passkey-only auth without inventing grants and
sessions," you still have a project left.

---

## Full application auth frameworks (plugins)

These own much more of the auth story for a typical SaaS or Next.js app.
Passkeys are usually one sign-in method among several.

### Better Auth

- **What it is:** Self-hosted TypeScript auth framework (sessions, OAuth, 2FA,
  orgs, admin, …) with a first-class
  [passkey plugin](https://better-auth.com/docs/plugins/passkey) powered by
  SimpleWebAuthn.
- **Approach:** Plugin API: `addPasskey`, `signIn.passkey`, list/update/delete
  passkeys, cookie sessions, schema adapters (Drizzle, Prisma, …). Passkeys
  attach to a broader identity model that usually includes other factors.
- **Strengths:** Integrated product surface, active ecosystem, "self-hosted
  Clerk" ambition, less ceremony plumbing than raw SimpleWebAuthn.
- **Gaps vs LocalWebAuthn:** Not passkey-_only_ by design; invitation-first
  bootstrap and recovery-as-policy are not the core product story. Heavier
  dependency and conceptual surface. You adopt an auth framework, not a small
  lifecycle module you can read end-to-end.
- **When to prefer it:** Multi-method auth, Next.js/SaaS defaults, org/RBAC
  plugins, willingness to take a full framework.

### Auth.js (NextAuth) Passkey provider

- **What it is:** Experimental WebAuthn/passkey provider for Auth.js, also
  SimpleWebAuthn-based, requiring a database adapter and an `Authenticator`
  table. Auth.js development has been moving under the Better Auth umbrella.
- **Approach:** Provider + experimental flag; custom pages use
  `signIn("passkey")` for register and authenticate.
- **Strengths:** Familiar if you already live in Auth.js; OAuth + sessions in
  one place.
- **Gaps:** Docs explicitly mark passkeys **experimental / not recommended for
  production**. Lifecycle opinions are thin compared with LocalWebAuthn's grant
  model. Future direction is tied to framework consolidation.
- **When to prefer it:** Existing Auth.js app exploring passkeys, not a greenfield
  passkey-only system.

### SuperTokens

- **What it is:** Open-source auth product (core service + SDKs) with passkey /
  WebAuthn recipes alongside passwordless, social, and session management.
- **Approach:** Recipe-driven flows, frontend SDKs, self-hosted or managed core.
  Passkeys are one recipe in a multi-method stack with fallbacks (OTP, magic
  link, password).
- **Strengths:** Production-oriented sessions, multi-language SDKs, operational
  story for teams that want an auth _service_.
- **Gaps vs LocalWebAuthn:** Separate process / operational surface; not a
  ~few-thousand-line in-process library. Enrollment and recovery still product
  policy, but shaped by SuperTokens' multi-factor model rather than invitation-
  only passkeys.
- **When to prefer it:** You want a dedicated auth service with SDKs, not a
  library inside the app process.

---

## Self-hosted auth platforms (passkey-forward)

### Hanko

- **What it is:** Open-source auth and user management API (Go backend + JS
  SDKs), passkey-first with passwords, passcodes, OAuth, SSO as configurable
  companions. Cloud and self-hosted.
- **Approach:** External auth API; your app validates sessions/JWTs. FIDO-oriented
  positioning ("auth for the passkey era").
- **Strengths:** Productized UX, multi-method fallbacks, mobile paths, managed
  option.
- **Gaps vs LocalWebAuthn:** Another service to run or pay for; user directory
  often lives in Hanko; not "embed a store in my SQLite file." Invitation-only
  internal tools can use it, but the architecture is IdP-shaped.
- **When to prefer it:** Passkey-forward product with fallbacks, willingness to
  run or buy an auth service.

### Other platforms (brief)

| Project                                    | Shape       | Passkeys                   | Notes                                       |
| ------------------------------------------ | ----------- | -------------------------- | ------------------------------------------- |
| **Keycloak** / **Authentik** / **Zitadel** | Full IdP    | Via WebAuthn plugins / MFA | Federation, realms, ops-heavy               |
| **FusionAuth**                             | Auth server | First-class WebAuthn       | Commercial + free tier; not a TS library    |
| **Corbado** / **Passage** / **Clerk**      | Hosted      | Product feature            | Fastest path; external trust and data plane |

These solve "we need authentication as a product," not "we need a readable
passkey lifecycle inside our TypeScript monolith."

---

## LocalWebAuthn's approach

LocalWebAuthn is an **opinionated lifecycle around SimpleWebAuthn**:

1. Host creates users (with a stable 32-byte WebAuthn user handle).
2. Host issues a one-time **enrollment grant** (hashed at rest; URL fragment
   delivery).
3. Browser exchanges the grant for a short enrollment session cookie.
4. Registration challenge is bound to that grant (or to an already-authenticated
   session for additional passkeys).
5. Verify registration atomically stores credential + completes grant + opens
   session (SQLite/Postgres transactions; D1 batch with documented limits).
6. Sign-in is discoverable-credential authentication with
   `userVerification: 'required'`; challenges are single-use; counters
   compare-and-swap.
7. Sessions are opaque hashed tokens with idle and absolute expiry.
8. Recovery is **not** automated: host identity-proofs, then
   `revokeUserAuthentication` + `issueEnrollment`.

Explicit non-goals (see [RATIONALE.md](RATIONALE.md)): email delivery, OAuth,
passwords, tenant RBAC, cookie framework glue, rate limiting, attestation
policy.

### What is deliberately different

| Dimension           | Typical framework / IdP             | LocalWebAuthn                                                                                        |
| ------------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Primary factor      | Password + optional passkey / OAuth | Passkey only                                                                                         |
| First credential    | Self-serve signup or email link     | Invitation / bootstrap grant                                                                         |
| User table          | Often owned by the auth product     | Owned by the host app                                                                                |
| Ceremony crypto     | Various                             | SimpleWebAuthn (swappable)                                                                           |
| Persistence         | ORM schemas or remote service       | Official SQLite / PostgreSQL / D1 stores + store interface                                           |
| Sessions            | Framework cookies / JWTs            | Opaque hashed tokens; host sets cookies                                                              |
| Recovery            | Email reset, SMS, support tools     | Host policy + re-enrollment; runnable dual-channel machine with waiting period and vetoes (examples) |
| Size / auditability | Large surface                       | ~4,000 lines of lifecycle code, shared SQL module                                                    |
| HTTP framework      | Often Next.js-shaped                | Framework-neutral service + thin browser client                                                      |
| Maturity            | Varies; some battle-tested          | Young (`2.x`) with a small user base, and says so                                                    |

### What is _not_ unique (and should not be sold as unique)

- **Passkeys themselves.** Phishing resistance and origin binding come from
  WebAuthn and the platform authenticator, not from this package.
- **Using SimpleWebAuthn.** Better Auth, Auth.js, and many tutorials do too.
- **Self-hosting.** Better Auth, SuperTokens, Hanko, and Keycloak all can.
- **"No third parties" in the npm sense.** Ceremony libraries and peer DB
  drivers remain.

### Distinctive claims that hold up under comparison

1. **Invitation-first as the default security model**, not an afterthought
   plugin. Enrollment grants are single-use, expiring, hashed, grant-generation
   bound, and replaceable with audit events.
2. **Passkey-only without a password or magic-link safety net baked in.**
   Frameworks usually keep fallbacks; LocalWebAuthn forces the recovery
   conversation into the open (see
   [Designing Recovery](../README-DETAIL.org)).
3. **Lifecycle + multi-engine store contract** (SQLite / Postgres / D1) with
   shared SQL and conformance tests — not only ceremony helpers, not a remote
   IdP.
4. **Host-owned users and authorization.** Auth is a module; it is not your
   product database.
5. **Small enough to review** as a security dependency on the authentication
   path, with an explicit youth disclaimer.

---

## Feature comparison (JS/TS-focused)

| Capability                          | SimpleWebAuthn | passwordless-id | Better Auth + passkey |   Auth.js passkey    |   SuperTokens    |      Hanko       |        **LocalWebAuthn**        |
| ----------------------------------- | :------------: | :-------------: | :-------------------: | :------------------: | :--------------: | :--------------: | :-----------------------------: |
| Ceremony generate/verify            |      Yes       |       Yes       |  Via SimpleWebAuthn   |  Via SimpleWebAuthn  |       Yes        |       Yes        |       Via SimpleWebAuthn        |
| Browser helper                      |      Yes       |       Yes       |          Yes          |         Yes          |       Yes        |       Yes        |      Yes (protocol client)      |
| Passkey-only mode                   |      N/A       |       N/A       |       Possible        |       Possible       |   Configurable   |   Configurable   |       **Default / only**        |
| Invitation enrollment grants        |       No       |       No        |       App-built       |      App-built       |  App / product   |  Product flows   |             **Yes**             |
| Hashed challenge + session tokens   |       No       |       No        |  Framework sessions   |  Framework sessions  | Service sessions | Service sessions |             **Yes**             |
| Atomic challenge consume            |      App       |       App       |       Framework       |      Framework       |     Service      |     Service      |         **Yes (store)**         |
| Additional passkey via session      |      App       |       App       |          Yes          |         Yes          |       Yes        |       Yes        |             **Yes**             |
| Credential counter CAS              |      App       |       App       |     Plugin/store      |       Adapter        |     Service      |     Service      |             **Yes**             |
| Official SQLite / PG / D1           |       No       |       No        |    Adapters (ORM)     |       Adapters       |    Own stack     |    Own stack     |             **Yes**             |
| Cookie / origin helpers             |       No       |       No        |  Framework internals  | Framework internals  | Service sessions | Service sessions |             **Yes**             |
| Signup + recovery proofing flow     |      App       |       App       |  Multi-method flows   |         App          |  Product flows   |  Product flows   | **Example kits (passkey-only)** |
| In-process library (no auth daemon) |      Yes       |       Yes       |          Yes          |         Yes          |    No (core)     |        No        |             **Yes**             |
| OAuth / password / email OTP        |       No       |       No        |          Yes          |         Yes          |       Yes        |       Yes        |             **No**              |
| Production maturity                 |      High      |     Medium      |     Growing fast      | Passkey experimental |       High       |   Medium–high    |         **Low (young)**         |
| Federation / enterprise IdP         |       No       |       No        |        Limited        |     OAuth focus      |       Yes        |       Yes        |             **No**              |

"App" means you implement it. "Product flows" means the platform's UX, not a
small typed API in your process.

---

## Approach review: design patterns in the wild

### Pattern A — Ceremony only (SimpleWebAuthn, passwordless-id)

**Good when:** You already have sessions and identity, or you are learning
WebAuthn.

**Failure mode:** Every team reimplements challenge TTL, replay, credential
counters, and bootstrap; subtle TOCTOU bugs are common.

**LocalWebAuthn stance:** Stand on Pattern A for crypto; formalize the rest.

### Pattern B — Multi-method auth framework (Better Auth, Auth.js, SuperTokens)

**Good when:** You need OAuth, passwords, or email for real users and want
passkeys as an upgrade path.

**Failure mode:** Passkeys become a secondary factor UX; recovery still goes
through the weakest method; the framework grows far beyond a small admin tool's
needs.

**LocalWebAuthn stance:** Reject multi-method defaults. If you need OAuth, use
Pattern B or C instead of bolting federation onto this package.

### Pattern C — Auth service / IdP (Hanko, Keycloak, hosted vendors)

**Good when:** Multiple apps, compliance, org SSO, or you want auth out of the
app process.

**Failure mode:** Ops and coupling; user data and auth policy live outside the
app; overkill for a single internal tool with a dozen users.

**LocalWebAuthn stance:** Stay in-process. One app, one user table, one HTTPS
origin.

### Pattern D — Grant-based passkey lifecycle (LocalWebAuthn)

**Good when:** You are replacing a password _system_ for a population you can
enroll deliberately — by administrator invitation or by automated proofing at
signup — keep auth in-process with your app, and accept that recovery is
proofing + re-enrollment rather than emailing a new secret. Matches the
[target audience](#target-audience).

**Failure mode:** Keeping email or SMS as a standing way into any account, which
puts the mailbox back in front of the passkey; mandatory passkeys for unvalidated
device/accessibility populations; treating "no third parties" as "zero npm
packages" or "users cannot use iCloud/Google passkey sync." Young codebase:
interface stability is not a long production track record.

---

## Choosing among them

| If you need…                                                                                 | Prefer                                                     |
| -------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| Correct WebAuthn crypto only                                                                 | SimpleWebAuthn (or passwordless-id for minimalism)         |
| Next.js SaaS with OAuth + optional passkeys                                                  | Better Auth (or SuperTokens / Auth.js if already invested) |
| Passkey-forward product with email fallbacks and a managed option                            | Hanko or a commercial passkey vendor                       |
| Enterprise SSO, SAML, many apps                                                              | Keycloak, Zitadel, Authentik, commercial IdP               |
| Passkey-only login, no auth IdP, own users + DB, enrollment by invitation or verified signup | **LocalWebAuthn**                                          |
| Email or SMS kept as a standing way into any account, or a permanent password fallback       | Not LocalWebAuthn's sweet spot                             |

---

## Honest weaknesses relative to state of the art

1. **Maturity and adoption.** SimpleWebAuthn, SuperTokens, and major IdPs have
   far more production hours. LocalWebAuthn documents this in README and
   SECURITY.md; treat it as young software on the auth path.
2. **No multi-method story.** Peers win when passkeys must coexist with
   passwords or social login.
3. **The host still owns HTTP, but no longer alone.** Cookie flags, `__Host-`
   names, and exact-origin checks ship as helpers, and the
   [starter](../examples/starter-hono) arrives with the six routes wired; rate
   limiting and bot defense remain yours. Frameworks still paper over more.
4. **No hosted control plane.** No dashboard SaaS, no multi-tenant admin UI out
   of the box (the demo is an example, not a product).
5. **Ceremony is not differentiated.** Crypto quality tracks SimpleWebAuthn; do
   not pick LocalWebAuthn _because_ of novel cryptography.
6. **D1 non-atomicity** is a real adapter limit (documented); SQLite/Postgres are
   preferred when available.
7. **Recovery is operational, not automatic.** Replacing passwords removes the
   familiar reset email; someone must still prove identity out of band. The
   [signup/recovery proofing machine](#dual-channel-email--phone-delivery-kit)
   now ships that flow as runnable example code — with a waiting period and
   vetoes — but operating it, and its abuse handling, is still your product.

---

## JS developer friction (and what now closes it)

LocalWebAuthn solves the hard **ceremony + lifecycle middle**. A typical JS web
app developer (Vite/Next + Hono/Express/Fastify, used to Auth.js, Better Auth,
Clerk, or “bcrypt + cookie”) does **not** abandon passkeys because option
generation is hard. They abandon them when the **rest of a shippable product**
is still empty — password ecosystems have decades of copy-paste defaults for
that rest. This section was originally written as a gap analysis; the starter
kits it called for have since shipped, so it now records what exists and what
deliberately remains yours.

### What the packages and examples provide

Beyond the lifecycle core (grants, hashed tokens, atomic challenge consume,
counters, sessions, multi-passkey, revocation, SQLite/Postgres/D1): cookie and
origin helpers on `@localwebauthn/server`, a wired six-route
[Hono starter](../examples/starter-hono), internal-only email/SMS delivery for
both app shapes ([`channels-node`](../examples/channels-node) for a
traditional server, [`channels-cf`](../examples/channels-cf) for Workers + D1),
and a [signup/recovery proofing state machine](#dual-channel-email--phone-delivery-kit)
the demo runs end to end. The bounce was never crypto; it was product and ops —
and most of the product half is now runnable code.

### Ranked friction, revisited

| #   | Friction                              | Password / multi-method stack         | LocalWebAuthn now                                                                                            |
| --- | ------------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| 1   | **Recovery product**                  | “Forgot password” is a form + email   | Runnable: admin re-enroll (demo) + self-serve re-proofing machine with waiting period and vetoes (examples)  |
| 2   | **Framework drop-in**                 | `getServerSession()`, providers       | `starter-hono`: six routes, session guard, origin check wired; copy `auth-routes.ts`                         |
| 3   | **Cookie / origin details**           | Often framework defaults              | `authCookieNames` / `cookieAttributes` / `isExactOrigin`; non-loopback `http://` refuses loudly              |
| 4   | **Signup state machine**              | Email + password + session            | `signupPhase` vocabulary + full proofing machine (`channels` `signup.ts`), demo-simulated end to end         |
| 5   | **Cross-device / lockout fear**       | Form works anywhere                   | Claim-on-reopen finishes enrollment on the preferred device; demo prompts a second passkey; copy kit partial |
| 6   | **Ops** (rate limits, audit, cleanup) | Tutorials often skip; vendors include | `onEvent` wiring demonstrated (sign-in cancels recovery); rate limits + `cleanup()` scheduling still yours   |
| 7   | **OAuth / growth**                    | Plugins everywhere                    | Out of scope by design — if you need OAuth, use Better Auth or an IdP                                        |
| 8   | **Maturity / blame**                  | Familiar stack to point at            | Young package on the auth path; unchanged, and says so                                                       |

**Complexity map**

```text
  Easy path (password ecosystem)          LocalWebAuthn path (now)
  ----------------------------            ------------------------
  npm i auth-framework                    npm i @localwebauthn/*
  enable EmailProvider                    copy starter-hono routes (wired)
  enable Credentials                      cookie/origin helpers (one import)
  copy LoginForm                          crib the demo UI
  "Forgot password" included              signup/recovery machine (examples)
  OAuth button                            (out of scope — leave)
  ship                                    rate limits + delivery credentials
```

The crypto column was always easier with LocalWebAuthn; the “ship login this
sprint” column is now comparable for the passkey-only shape. What stays
heavier than mediocre password auth is deliberate: recovery is proofing you
operate, and abuse handling is yours.

### Decision tree (when not to force passkey-only)

- Need Google/GitHub login or SAML soon → multi-method framework or IdP.
- Cannot operate identity proofing for lost phones → do not go passkey-only.
- Population’s devices/accessibility unvalidated → do not mandate passkeys.
- Will keep email/SMS as a standing way into every account forever → that
  undoes the passkey bet; use a different product shape.
- Want passkey-only, own users + DB, enrollment by grant → LocalWebAuthn.

### Starter kit roadmap

Ordered by impact for JS developers (not by cryptographic purity). Status is
tracked here as the kits land.

| Priority | Kit                           | Intent                                                                                                   | Status                                                                                                                                                                                                          |
| -------- | ----------------------------- | -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1**    | **Framework starters**        | Hono/Node (and later Next App Router) with the six routes, session guard, and origin check already wired | **Done** — `examples/starter-hono`; full UI remains `examples/demo`                                                                                                                                             |
| **2**    | **Recovery starter kits**     | Admin re-enroll (revoke then issue) as a first-class action; dual-channel self-serve as runnable code    | **Done** — demo **Re-enroll** + simulated dual-channel signup/recovery; shared proofing state machine + internal-only delivery in `examples/channels{,-node,-cf}`                                               |
| **3**    | **Cookie + origin helpers**   | One place for Secure / HttpOnly / SameSite / `__Host-` names and exact-origin checks                     | **Done** — `@localwebauthn/server` (`authCookieNames`, `cookieAttributes`, `isExactOrigin`, …)                                                                                                                  |
| **4**    | **Signup state machine**      | Host-owned phases: user created → enrollment issued → exchanged → enrolled; next-step helper             | **Done** — `signupPhase` helpers + the proofing machine in `examples/channels`; a grant-read store API (`listEnrollmentGrants`) is planned for 2.2.0 so phase facts derive from the store instead of host flags |
| **5**    | **Post-enroll UX kit**        | Prompt for a second passkey; clear lockout / last-credential messaging                                   | Partial — demo copy + claim-on-reopen device choice; no shared package yet                                                                                                                                      |
| **6**    | **Ops snippets**              | Rate-limit examples, `onEvent` → log/table, `cleanup()` scheduler                                        | Partial — demo wires `onEvent` (`credential.authenticated` cancels live recoveries); rate limits and `cleanup()` scheduling still open                                                                          |
| **7**    | **Browser / support matrix**  | Platform vs security key vs synced passkey; common failure modes                                         | Not started (docs)                                                                                                                                                                                              |
| **8**    | **“Don’t use us if…” wizard** | Up-front decision tree in README / COMPARISON                                                            | Partial — this section + target audience                                                                                                                                                                        |

#### Dual-channel (email + phone) delivery kit

The largest product gap after HTTP helpers and starters is **delivering** proof
and enrollment messages without making email/SMS a standing authenticator:

1. Prove email (OTP or signed link) — host policy.
2. Prove phone (SMS OTP) — host policy.
3. Create app user + `createUserHandle()`.
4. `issueEnrollment()` and deliver the fragment URL on a **bound** channel.
5. User registers a passkey; email/SMS are **not** kept as login methods.

**Shipped:** internal-only delivery for both app shapes, sharing one core.
`examples/channels` holds the fixed message templates (the only content
source), destination validation (`SMS_ALLOWED_PREFIXES`), fetch-based Twilio /
Resend senders, and `inviteAndDeliver` (issue grant → deliver → return **no
link**). `examples/channels-node` is the traditional-server variant (SMTP with
an application password + Twilio); `examples/channels-cf` is the
fully-Cloudflare variant (Workers + D1 issuing real grants, Resend + Twilio,
bearer-guarded invite route, Miniflare tests of the bundled source). **No
deployment exposes a send API** — anyone-can-POST `/send-email` routes are an
open relay and were removed by design.

**Signup proofing state machine** (`channels-core` `signup.ts`): each channel
gets one capability-free proof link (`#signup=<id>&channel=…&otp=…`); pressing
Confirm proves that channel; the enrollment grant is minted only when the last
required channel lands, and from then on **any channel's link claims the same
single-use enrollment** — finish on whichever device you prefer. Open proof
pages cooperate on the one server-side machine (re-presenting their OTP as a
poll) and flip to "create your passkey" when the final confirmation arrives.
Channels are open-ended: link-borne ones (email, SMS, chat) carry OTPs, and
host-attested ones (an existing-passkey assertion during recovery, TOTP) are
proved by the host directly.

**Recovery is not signup.** An attacker holding one compromised channel could
initiate re-enrollment and socially engineer the owner into confirming the
other — and the initiator is unknowable. The machine therefore restructures
authority and time rather than guessing: any valid channel OTP can **veto**
(terminal cancel, "this wasn't me" beside every Confirm); recovery completion
opens a **waiting period** during which the account is untouched and every
open proof page shows the countdown with a cancel; and — Signal-style — **any
successful sign-in with an existing passkey cancels** live recoveries (wired
through the `credential.authenticated` audit event). Only a mature, uncanceled
claim performs revoke-then-issue. The demo runs all of it with simulated
delivery, a ten-second demo window, and Playwright coverage of both the veto
and the sign-in cancel; administrators are excluded from self-serve recovery
entirely. LocalWebAuthn core stays free of Twilio/Resend/nodemailer
dependencies and of proofing policy.

That kit closes friction **#1** and **#4** delivery for self-serve without
reintroducing password reset. Prefer it over adding passwords to the core
package.

### Bottom line for JS developers

- LocalWebAuthn is **not** missing WebAuthn — and no longer missing most of the
  **product shell** password ecosystems normalize: cookie/origin helpers, a
  wired starter, signup sequencing, and runnable recovery are in the box.
- What remains yours is deliberate: rate limiting and bot defense, delivery
  credentials, and the operation of recovery proofing.
- OAuth and multi-method growth remain deliberately elsewhere; if you need
  them, pick a framework or IdP rather than bolting them onto this package.

### Review findings — implemented

An adversarial review of the first starter-kit iteration (August 2026) drove
this section's work. All of its findings are resolved: the anyone-can-POST
send-API worker was **replaced by the internal-only delivery architecture**
above; Miniflare suites run the **bundled real source**; the HTTP helpers
**refuse non-loopback `http://`** and validate cookie names/values against
RFC 6265; the starter gained authorization warnings, a duplicate-invite 409,
and deployment notes; SECURITY.md links the helpers it used to only describe;
and example version pins are bumped at release (RELEASING.md). One item
remains open by design and is tracked on the roadmap above: a grant-read store
API so `signupPhase` facts derive from the store (2.2.0). The full findings
live in this file's git history.

---

## Summary

The state of the art for **TypeScript WebAuthn ceremonies** is SimpleWebAuthn
(with passwordless-id as a minimal alternative). The state of the art for
**full-stack application auth with a passkey checkbox** is moving toward
frameworks like Better Auth and service products like SuperTokens and Hanko.
Hosted IdPs remain the default for teams that do not want to own auth.

LocalWebAuthn does not compete on breadth. It targets the audience above:

> Replace the password _system_ with passkeys only; keep authentication in your
> TypeScript app and database; depend at runtime on the user, your service, and
> HTTPS — not on a third-party identity provider — and enroll through explicit
> one-time grants, by invitation or verified signup, with recovery as proofing
> and re-enrollment rather than an email reset.

If that is your product shape, LocalWebAuthn is closer to the right abstraction
than a ceremony library alone or a multi-method IdP. If it is not, use the
ceremony library under a framework or service that matches your constraints —
and still read their recovery path as carefully as their signup path.

For project-local design intent, see [RATIONALE.md](RATIONALE.md). For security
boundaries and host duties, see [SECURITY.md](../SECURITY.md). For a worked
HTTP integration, see the demo under `examples/demo/`.
