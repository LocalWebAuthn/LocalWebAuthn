# Channels worker (Twilio SMS + Resend email)

Minimal **Cloudflare Worker** that sends:

- **SMS** via [Twilio Messages API](https://www.twilio.com/docs/sms/api/message-resource)
- **Email** via [Resend](https://resend.com/docs/api-reference/emails/send-email) (DKIM when your domain is verified in Resend)

This is **delivery infrastructure** for LocalWebAuthn hosts — OTP codes, enrollment
links, recovery notices — not an identity provider. Email and SMS must not become
standing login methods; prove control, then call `issueEnrollment()` in your app.

LocalWebAuthn core has **no** Twilio/Resend dependency. This example stays under
`examples/`.

## Routes

| Method | Path          | Body                                                        |
| ------ | ------------- | ----------------------------------------------------------- |
| `GET`  | `/`           | Usage text                                                  |
| `GET`  | `/health`     | `{ status: "ok" }`                                          |
| `POST` | `/send-sms`   | `{ "to": "+15551234567", "body": "…" }`                     |
| `POST` | `/send-email` | `{ "to": "user@example.com", "subject": "…", "html": "…" }` |

## Bindings

| Binding               | Purpose                                            |
| --------------------- | -------------------------------------------------- |
| `TWILIO_ACCOUNT_SID`  | Twilio account SID                                 |
| `TWILIO_AUTH_TOKEN`   | Twilio auth token                                  |
| `TWILIO_PHONE_NUMBER` | From number (E.164)                                |
| `RESEND_API_KEY`      | Resend API key                                     |
| `RESEND_FROM`         | From address on a **verified** domain              |
| `TWILIO_API_BASE`     | Optional (tests); default `https://api.twilio.com` |
| `RESEND_API_BASE`     | Optional (tests); default `https://api.resend.com` |

DKIM is not implemented in this worker. Verify the domain in the Resend dashboard
so Resend signs outbound mail for `RESEND_FROM`.

## Local test (no real credentials)

Use the flake shell so Node and Make match CI:

```console
nix develop
make install          # if needed
make test-channels    # or: make test  (includes this suite)
# outside the shell:
make nix-test-channels
```

Equivalent npm: `npm test --workspace @localwebauthn/channels-cf-worker`.

Tests cover:

1. Provider helpers with a mock `fetch` (correct URLs, Basic/Bearer auth, bodies).
2. Worker routing in-process.
3. **Miniflare** dispatch of the **bundled `src/` worker** (esbuild, built in the test) against a local mock HTTP origin — the shipped source, not a copy.

## Deploy (sketch)

```console
# wrangler.toml bindings / secrets for production
npx wrangler deploy
```

Example `wrangler.toml`:

```toml
name = "localwebauthn-channels"
main = "src/index.ts"
compatibility_date = "2025-01-01"

[vars]
RESEND_FROM = "enroll@your-verified-domain.com"
# Secrets: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER, RESEND_API_KEY
```

## Compose with LocalWebAuthn

```text
Signup / recovery (your app)          This worker
----------------------------          -----------
Prove email + phone (OTP)      ->     POST /send-sms, POST /send-email
createUserHandle + user row
issueEnrollment()              ->     POST /send-email|sms with enrollment URL
                                       (only to the bound address)
registerPasskey
```

Never send an enrollment fragment to an address supplied only on a recovery form.
See [docs/COMPARISON.md](../../docs/COMPARISON.md#dual-channel-email--phone-delivery-kit).
