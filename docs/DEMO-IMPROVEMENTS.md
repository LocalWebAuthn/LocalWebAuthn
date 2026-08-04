# Demo review and improvements (`improve/demo-clarity`)

Review of `examples/demo` as a simple demonstration of passkey-only auth and
user management (no passwords, no third-party IdP). Branch: `improve/demo-clarity`.

## Verdict: up-to-date, under-teaching

### Already solid (leave alone)

| Area                | Assessment                                                             |
| ------------------- | ---------------------------------------------------------------------- |
| Package wiring      | On `@localwebauthn/*` **2.0.0**; SQLite store + browser client correct |
| Lifecycle coverage  | Bootstrap, invite, first passkey, second passkey, logout/login, revoke |
| Architecture        | App owns `demo_clients`; package owns auth tables — correct boundary   |
| Adapter (`auth.ts`) | Readable Hono mapping of the six routes + cookies + origin check       |
| Tests               | API tests + Playwright virtual authenticators (real WebAuthn path)     |
| Honesty             | README already says not a production template                          |

The demo was not broken or out of date relative to 2.0.0. It was easy to **use**
and hard to **learn from** without reading the main package docs.

### Gaps vs the teaching goal

1. **Cold start dead end** — Opening `/` without the bootstrap URL only said
   "Sign in" with no pointer to the enrollment link from `make demo`.
2. **Silent product model** — No copy that this is passkeys only, no passwords,
   no IdP; email looked like a login/recovery channel.
3. **Recovery not demonstrated as a flow** — Separate "Issue link" and trash
   buttons; the documented **revoke-then-issue** order was not a first-class
   action.
4. **Enrollment callout thin** — Link only; no expiry or "open elsewhere" hint.
5. **"Clients" jargon** — Fine as domain language, weaker as a people-management
   story for newcomers.

Out of scope for this pass (still valid later):

- Shrinking `client.ts` (hand-rolled DOM is large but one-file readable)
- Scheduling `cleanup()` in the demo process
- Showing live audit events from `onEvent`
- Dual-admin recovery of the bootstrap administrator
- Regenerating README screenshots/cast after UI copy changes (run
  `npm run demo:screenshots` when cutting a release)

## Improvements on this branch

### Implemented

| Change                                                | Why                                                            |
| ----------------------------------------------------- | -------------------------------------------------------------- |
| Sign-in and enroll ledes + cold-start hint            | Teach invitation-first; avoid silent homepage failure          |
| Header / summary copy: passkeys only                  | Position against passwords and IdPs in the UI itself           |
| "People" / "Add person"; email as identifier note     | Avoid implying email login or reset                            |
| Enrollment callout: expiry + where to open            | Make the bearer link operationally clear                       |
| **Re-enroll** endpoint + button (revoke then issue)   | Demo the recovery pattern from the package README              |
| Keep plain revoke as secondary (icon)                 | Still need lockout-without-link                                |
| Passkeys section help text                            | Second device without a new link; last-passkey warning context |
| API + e2e coverage for re-enroll                      | Prevent regressions                                            |
| Demo README rewritten around "what you should notice" | Match COMPARISON audience framing                              |

### Deliberately not changed

- Still one SQLite file, Hono, Vite, no SPA framework — keeps the surface small.
- Still prints bootstrap URL to the terminal (correct for local demos).
- Still no password field anywhere (including fake ones "for comparison").

## Suggested walkthrough (after `make demo`)

1. Open the printed enrollment URL → create administrator passkey.
2. **Add person** → copy link → other browser profile → create passkey.
3. **Add passkey** on the second account → sign out → sign in with passkey.
4. As admin, **Re-enroll** that person → confirm → open recovery link on their
   side → new passkey (old ones dead).

That sequence is the product story in under five minutes.

## Follow-ups (optional)

1. Regenerate `docs/images/demo-*.png` and note UI text in DEMO.md.
2. Optional thin "Architecture" strip linking `auth.ts` line ranges for readers
   of the source.
3. If `client.ts` grows further, split presentational templates from event
   binding only — not a framework migration.
