# Channels core (shared)

The delivery code both runtime examples share. **There is no HTTP surface
here, and neither runtime example adds one**: sending email or SMS is an
internal function call from your application's own authorized routes. No
external API can make these deployments send anything.

| Piece          | What it fixes                                                                                       |
| -------------- | --------------------------------------------------------------------------------------------------- |
| `templates.ts` | The **only** source of message content — callers pass a URL or code, never copy                     |
| `validate.ts`  | E.164 + `SMS_ALLOWED_PREFIXES` country allowlist (SMS-pumping defense)                              |
| `twilio.ts`    | fetch-based Twilio sender, identical under Node and Workers                                         |
| `resend.ts`    | fetch-based Resend sender (the Workers email transport)                                             |
| `deliver.ts`   | `inviteAndDeliver`: issue grant → deliver → return **no link**; revoke grant if no channel accepted |
| `signup.ts`    | Self-serve proofing state machine: capability-free proof links, claim-on-reopen                     |

Because content is template-only, the blast radius of a leaked credential or a
buggy caller is "our own enrollment/OTP copy, at our rate" — a cost problem,
never an arbitrary-content phishing relay from your domain or number.

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
