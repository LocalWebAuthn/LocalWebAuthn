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
[Designing Recovery](../README.md#designing-recovery).

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
  [Designing Recovery](../README.md#designing-recovery)).
- Operators who care that the authentication path is **small enough to read**
  (~3,500 lines of lifecycle code on top of SimpleWebAuthn).

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

[Designing Recovery](../README.md#designing-recovery) covers the same two-channel
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

| Dimension           | Typical framework / IdP             | LocalWebAuthn                                                  |
| ------------------- | ----------------------------------- | -------------------------------------------------------------- |
| Primary factor      | Password + optional passkey / OAuth | Passkey only                                                   |
| First credential    | Self-serve signup or email link     | Invitation / bootstrap grant                                   |
| User table          | Often owned by the auth product     | Owned by the host app                                          |
| Ceremony crypto     | Various                             | SimpleWebAuthn (swappable)                                     |
| Persistence         | ORM schemas or remote service       | Official SQLite / PostgreSQL / D1 stores + store interface     |
| Sessions            | Framework cookies / JWTs            | Opaque hashed tokens; host sets cookies                        |
| Recovery            | Email reset, SMS, support tools     | Host policy + re-enrollment; documented social-engineering bar |
| Size / auditability | Large surface                       | ~3,500 lines of lifecycle code, shared SQL module              |
| HTTP framework      | Often Next.js-shaped                | Framework-neutral service + thin browser client                |
| Maturity            | Varies; some battle-tested          | Young (`2.x`) with a small user base, and says so              |

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
   [Designing Recovery](../README.md#designing-recovery)).
3. **Lifecycle + multi-engine store contract** (SQLite / Postgres / D1) with
   shared SQL and conformance tests — not only ceremony helpers, not a remote
   IdP.
4. **Host-owned users and authorization.** Auth is a module; it is not your
   product database.
5. **Small enough to review** as a security dependency on the authentication
   path, with an explicit youth disclaimer.

---

## Feature comparison (JS/TS-focused)

| Capability                          | SimpleWebAuthn | passwordless-id | Better Auth + passkey |   Auth.js passkey    |   SuperTokens    |      Hanko       |   **LocalWebAuthn**   |
| ----------------------------------- | :------------: | :-------------: | :-------------------: | :------------------: | :--------------: | :--------------: | :-------------------: |
| Ceremony generate/verify            |      Yes       |       Yes       |  Via SimpleWebAuthn   |  Via SimpleWebAuthn  |       Yes        |       Yes        |  Via SimpleWebAuthn   |
| Browser helper                      |      Yes       |       Yes       |          Yes          |         Yes          |       Yes        |       Yes        | Yes (protocol client) |
| Passkey-only mode                   |      N/A       |       N/A       |       Possible        |       Possible       |   Configurable   |   Configurable   |  **Default / only**   |
| Invitation enrollment grants        |       No       |       No        |       App-built       |      App-built       |  App / product   |  Product flows   |        **Yes**        |
| Hashed challenge + session tokens   |       No       |       No        |  Framework sessions   |  Framework sessions  | Service sessions | Service sessions |        **Yes**        |
| Atomic challenge consume            |      App       |       App       |       Framework       |      Framework       |     Service      |     Service      |    **Yes (store)**    |
| Additional passkey via session      |      App       |       App       |          Yes          |         Yes          |       Yes        |       Yes        |        **Yes**        |
| Credential counter CAS              |      App       |       App       |     Plugin/store      |       Adapter        |     Service      |     Service      |        **Yes**        |
| Official SQLite / PG / D1           |       No       |       No        |    Adapters (ORM)     |       Adapters       |    Own stack     |    Own stack     |        **Yes**        |
| In-process library (no auth daemon) |      Yes       |       Yes       |          Yes          |         Yes          |    No (core)     |        No        |        **Yes**        |
| OAuth / password / email OTP        |       No       |       No        |          Yes          |         Yes          |       Yes        |       Yes        |        **No**         |
| Production maturity                 |      High      |     Medium      |     Growing fast      | Passkey experimental |       High       |   Medium–high    |    **Low (young)**    |
| Federation / enterprise IdP         |       No       |       No        |        Limited        |     OAuth focus      |       Yes        |       Yes        |        **No**         |

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
3. **Host must build HTTP correctly.** Cookies, exact origin, rate limits remain
   yours. Frameworks paper over more of that — mitigated over time by the
   [starter kit](#starter-kit-roadmap) below.
4. **No hosted control plane.** No dashboard SaaS, no multi-tenant admin UI out
   of the box (the demo is an example, not a product).
5. **Ceremony is not differentiated.** Crypto quality tracks SimpleWebAuthn; do
   not pick LocalWebAuthn _because_ of novel cryptography.
6. **D1 non-atomicity** is a real adapter limit (documented); SQLite/Postgres are
   preferred when available.
7. **Recovery is operational, not automatic.** Replacing passwords removes the
   familiar reset email; someone must still prove identity out of band.

---

## JS developer friction (why teams still ship passwords)

LocalWebAuthn solves the hard **ceremony + lifecycle middle**. A typical JS web
app developer (Vite/Next + Hono/Express/Fastify, used to Auth.js, Better Auth,
Clerk, or “bcrypt + cookie”) does **not** abandon passkeys because option
generation is hard. They abandon them when the **rest of a shippable product**
is still empty — and password ecosystems have decades of copy-paste defaults
for that rest.

### What is already easy

If the problem is “I don’t want raw WebAuthn,” LocalWebAuthn is already ahead
of SimpleWebAuthn alone: grants, hashed tokens, challenge consume, counters,
sessions, multi-passkey, revocation, SQLite/Postgres/D1, and a readable HTTP
adapter pattern. The bounce is not crypto; it is product and ops.

### Ranked friction

| #   | Friction                              | Password / multi-method stack         | LocalWebAuthn today                                                    |
| --- | ------------------------------------- | ------------------------------------- | ---------------------------------------------------------------------- |
| 1   | **Recovery product**                  | “Forgot password” is a form + email   | Host designs proofing + re-enrollment; correct, but no default widget  |
| 2   | **Framework drop-in**                 | `getServerSession()`, providers       | Six routes, cookies, origin checks are host code                       |
| 3   | **Cookie / origin details**           | Often framework defaults              | Easy to get wrong once (`__Host-`, Secure, preview URLs)               |
| 4   | **Signup state machine**              | Email + password + session            | Create user → prove channels → `issueEnrollment` → exchange → register |
| 5   | **Cross-device / lockout fear**       | Form works anywhere                   | Multi-passkey + recovery playbook required                             |
| 6   | **Ops** (rate limits, audit, cleanup) | Tutorials often skip; vendors include | SECURITY.md assigns them to the host (honest, more perceived work)     |
| 7   | **OAuth / growth**                    | Plugins everywhere                    | Out of scope by design — path of least resistance becomes Better Auth  |
| 8   | **Maturity / blame**                  | Familiar stack to point at            | Young package on the auth path                                         |

**Complexity map**

```text
  Easy path (password ecosystem)          LocalWebAuthn path
  ----------------------------            ------------------
  npm i auth-framework                    npm i @localwebauthn/*
  enable EmailProvider                    design enrollment delivery
  enable Credentials                      write 6 routes + cookies + origin
  copy LoginForm                          map users + createUserHandle
  "Forgot password" included              design recovery ops
  OAuth button                            (out of scope — leave)
  ship                                    rate limits, audit, multi-passkey UX
```

The crypto column is easier with LocalWebAuthn. The “ship login this sprint”
column is still heavier than mediocre password auth unless starter kits close
the gap.

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

| Priority | Kit                           | Intent                                                                                                   | Status                                                                                                                                     |
| -------- | ----------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **1**    | **Framework starters**        | Hono/Node (and later Next App Router) with the six routes, session guard, and origin check already wired | **Done** — `examples/starter-hono`; full UI remains `examples/demo`                                                                        |
| **2**    | **Recovery starter kits**     | Admin re-enroll (revoke then issue) as a first-class action; dual-channel self-serve as runnable code    | Partial — demo **Re-enroll**; internal-only delivery in `examples/channels{,-node,-cf}` (SMTP/Resend + Twilio); full OTP signup still open |
| **3**    | **Cookie + origin helpers**   | One place for Secure / HttpOnly / SameSite / `__Host-` names and exact-origin checks                     | **Done** — `@localwebauthn/server` (`authCookieNames`, `cookieAttributes`, `isExactOrigin`, …)                                             |
| **4**    | **Signup state machine**      | Host-owned phases: user created → enrollment issued → exchanged → enrolled; next-step helper             | **Done** — `signupPhase` / `describeSignupPhase` on `@localwebauthn/server`                                                                |
| **5**    | **Post-enroll UX kit**        | Prompt for a second passkey; clear lockout / last-credential messaging                                   | Partial — demo copy; no shared package yet                                                                                                 |
| **6**    | **Ops snippets**              | Rate-limit examples, `onEvent` → log/table, `cleanup()` scheduler                                        | Not started                                                                                                                                |
| **7**    | **Browser / support matrix**  | Platform vs security key vs synced passkey; common failure modes                                         | Not started (docs)                                                                                                                         |
| **8**    | **“Don’t use us if…” wizard** | Up-front decision tree in README / COMPARISON                                                            | Partial — this section + target audience                                                                                                   |

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

**Still open:** end-to-end OTP verify → `issueEnrollment` glue (the `otp`
templates and senders exist; the verification state machine is host policy).
LocalWebAuthn core stays free of Twilio/Resend/nodemailer dependencies.

That kit closes friction **#1** and **#4** delivery for self-serve without
reintroducing password reset. Prefer it over adding passwords to the core
package.

### Bottom line for JS developers

- LocalWebAuthn is **not** missing WebAuthn.
- It was missing the **product shell** password ecosystems normalize: recovery
  defaults, framework glue, cookie helpers, signup sequencing, ops snippets.
- Helpers and starters shrink that shell; dual-channel examples shrink recovery
  and signup fear. OAuth and multi-method growth remain deliberately elsewhere.

### Review Findings

A full review (August 2026) of the first starter-kit branch — HTTP/signup
helpers (kits #3/#4), the Hono starter (#1), and the delivery worker (part of
#2) — recorded these findings to direct the next development sessions. The
review verified a green baseline first, all inside the flake shell:
`make nix-check` (typecheck, lint, format, coverage thresholds, publint,
arethetypeswrong) and `make nix-test-demo` (Playwright lifecycle e2e) pass; the
channels worker suite passes; committed `dist/` matches a fresh rebuild; the
starter's routes match the `@localwebauthn/browser` defaults (`/api/auth`
base path, `{ token }` exchange body); tokens are lowercase base32, so raw
cookie round-trips are safe; `examples/**` is covered by root typecheck and
lint.

| #   | Severity | Finding                                                        | Where                            |
| --- | -------- | -------------------------------------------------------------- | -------------------------------- |
| 1   | **High** | Channels worker is an unauthenticated SMS / email relay        | resolved: `examples/channels*`   |
| 2   | Medium   | Miniflare test runs a hand-copied script, not the real worker  | `tests/worker.miniflare.test.ts` |
| 3   | Medium   | `SignupFacts` are not observable through the package API       | store contract + both consumers  |
| 4   | Low      | Starter invite authorization, duplicate-email 500, README gaps | `examples/starter-hono`          |
| 5   | Low      | HTTP helper polish (validation, `http://` downgrade, types)    | `packages/server/src/http.ts`    |
| 6   | Low      | Docs and release hygiene (links, version pins, Make vs npm)    | repo-wide                        |

**Status (August 2026):** #1 is **resolved by architecture** — the standalone
send-API worker was replaced by internal-only delivery (`examples/channels`,
`-node`, `-cf`): fixed templates, no send routes, bearer-guarded app flow,
country-prefix allowlists. #2, #5, and #6 are **done** (Miniflare bundles the
real source; helpers reject non-loopback HTTP and validate cookie octets;
SECURITY.md links the helpers, `make check` delegates to `npm run check`,
RELEASING.md pins example versions at release). #4 is done except the
`basePath` parameter (mount-order note added instead). #3 — the grant-read
store API — remains open as 2.2.0 contract work.

#### 1. Channels worker must ship secure by default (high)

`POST /send-sms` and `POST /send-email` accept requests from **anyone** — no
caller authentication of any kind — and the README's deploy sketch publishes
the worker with `wrangler deploy`. Deployed as-is it is SMS-pumping fraud
infrastructure (scripted sends to premium-rate numbers on the host's Twilio
bill) and a phishing relay from the DKIM-verified `RESEND_FROM` domain. The
existing caveat ("do not accept an attacker-supplied address") assumes an
honest caller — the wrong attacker. Direction:

- Require a `CHANNELS_AUTH_TOKEN` secret binding, checked with a timing-safe
  compare against `Authorization: Bearer …`; fail closed (401, and refuse to
  serve when the binding is unset).
- README: a prominent "Protect this endpoint" section — Cloudflare service
  bindings or Access (never internet-reachable), rate limits, destination
  country allowlist, and the cost blast radius of getting this wrong.
- Stop relaying upstream Twilio/Resend response bodies and thrown
  `error.message`s (which name missing bindings) verbatim to untrusted
  callers.

#### 2. Miniflare test must execute the real worker (medium)

`worker.miniflare.test.ts` feeds Miniflare a hand-copied inline script ("same
public contract as `src/`") — and it has already drifted: the inline copy
returns upstream responses verbatim while `src/index.ts` re-wraps them with
its own `Content-Type` / `Cache-Control` headers. The shipped source is only
exercised in-process under Node, so edits to `src/` cannot fail the Miniflare
test. Direction: bundle the real source (one esbuild call in `beforeAll`) or
adopt `@cloudflare/vitest-pool-workers` so tests run the actual module inside
workerd; otherwise soften the "Miniflare-tested" claims here and in the
worker README.

#### 3. Make `SignupFacts` observable (medium — API gap)

`signupPhase` warns against ad-hoc pending flags, but the store contract has
no grant **read** (`replaceEnrollmentGrant` is write-only), so both consumers
on this branch invent exactly those flags:

- The demo feeds `hasPendingEnrollmentGrant: passkeyCount === 0` — degenerate
  (only 2 of 4 phases are reachable), and the demo UI never renders the new
  `signupPhase` / `signupPhaseLabel` payload fields.
- The starter's `pending_enrollment` column is set on issue but never cleared
  when the invitee enrolls, and goes wrong after grant expiry or
  `revokeUserAuthentication`.

Direction (either): add `hasPendingEnrollment(userId)` or
`listEnrollmentGrants(userId)` (metadata only — issuedAt / expiresAt /
approvedBy, never token material) to the service and store contract, enabling
a `signupPhaseFor(auth, userId)` convenience; or wire the starter's flag to
`onEvent` (`enrollment.completed`, `enrollment.revoked`,
`user.authentication_revoked` already exist), which doubles as the roadmap #6
ops snippet. Until one lands, roadmap #4 above is honestly **Partial —
vocabulary shipped; facts not yet derivable from the store**, and the
CHANGELOG's "without inventing ad-hoc pending flags" oversells.

#### 4. Starter hardening (low, but it is the copy-paste artifact)

- `/api/invite`: **any** authenticated session can mint users and enrollment
  grants (the demo gates on administrator; the starter has no roles). Add a
  loud comment ("add your role check here") and a README bullet.
- Re-inviting an existing email hits the `UNIQUE` constraint and surfaces as
  an unhandled 500; catch it and return 409.
- README gaps: POSTs require an `Origin: http://localhost:4180` header (there
  is no UI — people will curl and hit `invalid_origin` with no hint);
  restarting with zero credentials revokes the old bootstrap link and prints a
  fresh one (nice property — say it); the `127.0.0.1` bind plus
  `STARTER_PUBLIC_ORIGIN`-derived `Secure` cookies is exactly right behind a
  TLS-terminating proxy — one sentence would market the helpers' best feature.
- `mountPasskeyAuth` hardcodes `'/api/*'` while the browser client takes a
  `basePath`; parameterize it, and note that the origin middleware must be
  mounted before any host routes it should protect.

#### 5. HTTP helper polish (low)

- `serializeCookie` interpolates name and value unvalidated — safe for base32
  tokens, but it is exported general-purpose API: assert RFC 6265
  cookie-octets (or document "LocalWebAuthn tokens only").
- `parseCookieHeader` does no percent-decoding while Hono's `setCookie`
  percent-encodes; add a doc line so nobody uses it as a general cookie
  parser.
- `isHttpsPublicOrigin` silently downgrades **any** `http://` origin — not
  just loopback — to plain, non-`Secure` cookie names, though the docstring
  frames plain names as a localhost concession. Warn or throw on non-loopback
  `http://` so a misconfigured `publicOrigin` fails loudly.
- `AuthCookieKind` is exported but unused: define
  `AuthCookieNames = Record<AuthCookieKind, string>` or drop it.
- `serializeCookie` hardcodes `HttpOnly` / `SameSite=Strict` instead of
  deriving them from its argument — consistent while the type pins them,
  brittle if `CookieAttributes` ever loosens.

#### 6. Documentation and release hygiene (low)

- SECURITY.md's host-duty bullets (cookies, exact origin) now have first-party
  implementations — link `authCookieNames` / `cookieAttributes` /
  `isExactOrigin` there. `http.ts` already points at SECURITY.md; make the
  pointer bidirectional.
- Both examples pin `"@localwebauthn/server": "2.0.0"` but import unreleased
  APIs; that resolves in-workspace and breaks when an example is copied out.
  Bump the pins at release (checklist item in docs/RELEASING.md) or note it in
  the example READMEs until the next version ships.
- `make check` re-lists the package.json `check` steps and inserts
  `ensure-postgres`; two sources of truth will drift — have one delegate to
  the other.

#### What held up under review

The demo refactor is a real dedup and a behavioral improvement (normalized
exact-origin comparison instead of string equality, so
`https://app.example.com:443` now matches). `__Host-` naming honors Hono's
prefix validation (Secure, `Path=/`); challenge cookies are cleared before
verification; `serializeClearedCookie` and the `maxAge >= 1` clamp are
correct. The injectable-`fetch` provider tests keep credentials out of CI.
The Makefile/flake tiers (`test`, `test-postgres`, `test-channels`,
`test-demo`, `nix-%`) work as documented.

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
