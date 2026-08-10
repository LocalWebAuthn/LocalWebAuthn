# Channels core (shared)

The delivery code both runtime examples share. **There is no HTTP surface
here, and neither runtime example adds one**: sending email or SMS is an
internal function call from your application's own authorized routes. No
external API can make these deployments send anything.

| Piece          | What it fixes                                                                   |
| -------------- | ------------------------------------------------------------------------------- |
| `templates.ts` | The **only** source of message content — callers pass a URL or code, never copy |
| `validate.ts`  | E.164 + `SMS_ALLOWED_PREFIXES` country allowlist (SMS-pumping defense)          |
| `twilio.ts`    | fetch-based Twilio sender, identical under Node and Workers                     |
| `resend.ts`    | fetch-based Resend sender (the Workers email transport)                         |
| `deliver.ts`   | `inviteAndDeliver`: issue grant → deliver → return **no link** to the caller    |
| `signup.ts`    | Self-serve proofing state machine: capability-free proof links, claim-on-reopen |

Because content is template-only, the blast radius of a leaked credential or a
buggy caller is "our own enrollment/OTP copy, at our rate" — a cost problem,
never an arbitrary-content phishing relay from your domain or number.

## Integration map

| Need                                              | Use                                                                          |
| ------------------------------------------------- | ---------------------------------------------------------------------------- |
| Passkey lifecycle (grants, sessions, credentials) | `@localwebauthn/server` + `@localwebauthn/browser`                           |
| Cookie names / attributes / exact origin          | `authCookieNames`, `cookieAttributes`, `isExactOrigin` on the server package |
| Issue a grant and deliver the enrollment URL      | `inviteAndDeliver` + `channels-node` or `channels-cf` delivery               |
| Dual-channel proof before any grant exists        | `signup.ts` helpers + your signup table (see demo)                           |
| Full UI reference                                 | `examples/demo`                                                              |

Server `signupPhase` (credential and grant facts for admin tables) is **not** the
same as channels `signup.ts` (multi-channel OTP proofing). The first answers "does
this user have a passkey yet?". The second answers "have they proved email and
phone?".

## Signup and recovery, in sequence

### Plain self-serve signup

```text
Visitor                    Your app                         Channels / LocalWebAuthn
   |                           |                                      |
   |-- submit email+phone ---->|                                      |
   |                           |-- createSignupChallenge() ---------->|
   |                           |-- store otpHashes, send proof links ->| (email+SMS)
   |<- open email proof link --|                                      |
   |-- confirm OTP ----------->|-- verifySignupProof -> proved        |
   |<- open SMS proof link ----|                                      |
   |-- confirm OTP ----------->|-- last channel: issueEnrollment() -->|
   |                           |-- completeSignup(store token)        |
   |<- enrollmentToken --------|                                      |
   |-- registerPasskey ------->|-- exchange + verifyRegistration ---->|
```

No enrollment grant exists until every required channel is proved. The proof links
are therefore capability-free while they ride email and SMS.

### Recovery of an account that already has passkeys

```text
Requester                  Your app                         Existing owner
   |                           |                                  |
   |-- start recovery -------->|-- proof links to bound channels  |
   |                           |                                  |
   |-- confirm channels ------>|-- mark pending; claimableAt=now+D|
   |                           |-- notify all channels ----------->|
   |                           |   (account still unchanged)      |
   |  [waiting period]         |                                  |
   |                           |<-- "this wasn't me" cancel OTP ---|  (veto)
   |                           |   OR passkey sign-in cancels     |
   |                           |                                  |
   |-- claim after claimableAt |-- revokeUserAuthentication       |
   |                           |-- issueEnrollment                |
   |<- enrollmentToken --------|                                  |
```

Confirming is weak authority. **Canceling is strong.** The delay before a claim
gives the owner time to veto. Production `D` is hours, not the demo's few seconds.

### Claim-on-reopen, and what it costs

After plain signup completes, any valid channel OTP may claim the same single-use
enrollment until the signup expires. The person can therefore finish on a second
device without a second message. That is deliberate.

The window this opens cannot be closed by shortening it. Confirming on a phone, then
a laptop, then going back to the phone is exactly the behaviour claim-on-reopen exists
to allow, so a short post-completion window breaks the feature it is meant to protect.
What closes it is making the outcome visible: `passkeyCreatedEmail` and
`passkeyCreatedSms` go to every bound channel the moment a credential exists, whoever
created it. A person who did not create it finds out without having to come back and
discover a failure.

Consequences an operator should still know, tracked in
[issue #10](https://github.com/LocalWebAuthn/LocalWebAuthn/issues/10):

- **The window is the rest of the proofing TTL.** `completeSignup` sets
  `consumed_at` but does not shorten `expires_at`, so a person who confirms both
  channels quickly leaves nearly the full 15 minutes claimable. Recovery already
  does the opposite — `markSignupPending` resets `expires_at` — so there is a
  precedent to copy.
- **Two clocks, not one.** The signup row's `expires_at` bounds the _claim_.
  `enrollmentGrantMs` (30 minutes by default) bounds the _exchange_ by whoever
  holds the token. Shortening one does not shorten the other.
- **A second claim is still silent; a second _exchange_ is not.** A grant is spent at
  exchange, not at claim, and the demo re-serves the stored token to every valid OTP,
  so the extra claim itself leaves no trace. What has changed is the outcome for
  whoever loses the race: `exchangeEnrollment` now reports `enrollmentState: 'used'`
  rather than a generic "invalid or expired", so the person is told the link was
  already spent and what to do if it was not them. The server also emits
  `enrollment.rejected` carrying the `userId`, which is the hook for notifying every
  bound channel. The remaining gap is at claim time: nothing counts claims, so a host
  still cannot see the extra claim before the exchange fails.
- **The token sits at rest.** Re-serving one token means storing it:
  `demo_signups.enrollment_token` holds a live capability until the row is reaped.
  Minting a fresh grant per claim would avoid that, and `supersededGrantIds` would
  then be the detection signal — at the cost of making the last claimant win.

## The two runtimes

|                | [`channels-node`](../channels-node) (traditional server) | [`channels-cf`](../channels-cf) (fully Cloudflare) |
| -------------- | -------------------------------------------------------- | -------------------------------------------------- |
| Email          | **SMTP** + application password (nodemailer)             | **Resend** HTTP API (Workers cannot speak SMTP)    |
| SMS            | Twilio (shared)                                          | Twilio (shared)                                    |
| Secrets live   | Server environment                                       | Worker secrets                                     |
| Sending is     | In-process function call                                 | In-worker function call                            |
| Public surface | None added                                               | None added (only the app's own guarded routes)     |

What neither solves — deliberately, because only the host can: **signup
abuse**. Anyone can type addresses into your onboarding form, and every
"we will email whatever you enter" flow can be made to spam your fixed copy.
Rate-limit per IP and per destination, put Turnstile/CAPTCHA in front of the
form, create no user row until the first proof succeeds, and set provider
spend alerts. Templates cap what that abuse can say; only your flow controls
how often it happens.

## Test

```console
nix develop
make test-channels    # core + node + cf suites
```
