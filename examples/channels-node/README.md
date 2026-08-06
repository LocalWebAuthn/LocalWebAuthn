# Channels: traditional Node server (SMTP + Twilio)

Delivery for apps with an ordinary server process: email over **SMTP with an
application-specific password**, SMS via **Twilio**, both invoked internally.
There is no send endpoint — the security model is that only your own routes
can reach these functions.

## Use

```ts
import { createDelivery, inviteAndDeliver } from '@localwebauthn/channels-node';

const delivery = createDelivery(process.env);

// Inside your authorized invite/signup route:
const outcome = await inviteAndDeliver(auth, delivery, {
  userId,
  to: { email: 'person@example.com', phone: '+15551234567' },
});
return c.json({ delivered: outcome.delivered, expiresAt: outcome.expiresAt });
// The enrollment URL is not in `outcome` — its only copy went to the person.
```

`delivery.otp(to, { code })` sends channel-proof codes for self-serve signup
the same way. All copy comes from the fixed templates in
[`channels-core`](../channels); this module only chooses transports.

## Configuration

| Variable                                                           | Purpose                                                        |
| ------------------------------------------------------------------ | -------------------------------------------------------------- |
| `SMTP_URL`                                                         | `smtps://user%40example.com:app-password@smtp.example.com:465` |
| `SMTP_FROM`                                                        | `"Example" <enroll@example.com>`                               |
| `TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN` / `TWILIO_PHONE_NUMBER` | Twilio credentials and sending number                          |
| `SMS_ALLOWED_PREFIXES`                                             | e.g. `+1,+44` — refuse other destinations                      |
| `APP_NAME`                                                         | Name used in the message copy                                  |

Unconfigured channels are absent from `delivery.channels` and throw loudly if
used — never a silent skip. DKIM/SPF are your mail domain's setup, as for any
mail the server sends.

## Test (no network, no credentials)

```console
nix develop
make test-channels
```

The suite drives a real `LocalWebAuthn` grant through `inviteAndDeliver` with
nodemailer's buffered stream transport and a mocked Twilio `fetch`, and
asserts the one-time link reaches both channels while the caller's response
contains no token.
