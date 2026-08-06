# Channels: fully Cloudflare (Workers + D1, Resend + Twilio)

Delivery for apps with **no traditional server**: the Worker owns the users
table and LocalWebAuthn state in **D1**, issues enrollment grants, and
delivers them via **Resend** (email — Workers cannot speak SMTP) and
**Twilio** (SMS), all inside the Worker.

**There is no send API.** The old `/send-email` / `/send-sms` shape is gone:
anyone who could reach such routes could spend your Twilio balance and send
DKIM-signed mail from your domain. Here the only public route is the app's own
flow, and it:

- requires a bearer token (`INVITE_API_TOKEN`, fail-closed) standing in for
  your real session/admin authorization;
- sends **only the fixed templates** from [`channels-core`](../channels);
- returns `{ delivered, expiresAt }` — **never** the enrollment link.

## Routes

| Method | Path          | Body                             | Guard                                      |
| ------ | ------------- | -------------------------------- | ------------------------------------------ |
| `GET`  | `/health`     | —                                | none                                       |
| `POST` | `/api/invite` | `{ email, displayName, phone? }` | `Authorization: Bearer <INVITE_API_TOKEN>` |

Everything else is 404. In a real app, replace the bearer check with your
session middleware (see `examples/starter-hono`) and add rate limiting.

## Bindings

| Binding                                                            | Purpose                                   |
| ------------------------------------------------------------------ | ----------------------------------------- |
| `AUTH` (D1)                                                        | Users table + LocalWebAuthn tables        |
| `INVITE_API_TOKEN`                                                 | Secret; route refuses without it          |
| `PUBLIC_ORIGIN` / `APP_NAME`                                       | App identity for URLs and copy            |
| `RESEND_API_KEY` / `RESEND_FROM`                                   | Email (domain verified in Resend → DKIM)  |
| `TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN` / `TWILIO_PHONE_NUMBER` | SMS                                       |
| `SMS_ALLOWED_PREFIXES`                                             | e.g. `+1,+44` — refuse other destinations |
| `TWILIO_API_BASE` / `RESEND_API_BASE`                              | Tests only                                |

Example `wrangler.toml`:

```toml
name = "localwebauthn-channels-cf"
main = "src/worker.ts"
compatibility_date = "2026-07-29"

[[d1_databases]]
binding = "AUTH"
database_name = "localwebauthn"
database_id = "..."

[vars]
PUBLIC_ORIGIN = "https://app.example.com"
APP_NAME = "Example"
RESEND_FROM = "enroll@example.com"
SMS_ALLOWED_PREFIXES = "+1"
# Secrets (wrangler secret put): INVITE_API_TOKEN, RESEND_API_KEY,
# TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER
```

## Test (no network, no credentials)

```console
nix develop
make test-channels
```

Miniflare runs the **bundled real source** (esbuild in the test) with a real
D1 database and mock provider origins, and asserts: no send routes exist,
invites fail closed without the token, the grant lands on D1, the one-time
link reaches both providers inside the fixed templates, and the caller's
response contains no token.
