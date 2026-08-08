# Provisioning a script credential with a human's passkey

How a person whose passkey lives in the macOS Passwords keystore authorizes a script to
call the API, and what the script ends up holding.

**Status.** This describes the flow against the design in `DESIGN-MACHINE-CREDENTIALS.md`
and `CONSENSUS.md`. As shipped, `@localwebauthn/server@2.2.0` has no `kind` column and
there is no `@localwebauthn/client` package; issue #11 is open. The server-side calls below
that already exist are named as they exist; the proposed additions are marked.

## The constraint that shapes everything

An Apple Passwords passkey is a **synced platform credential**. It is reachable only
through `navigator.credentials.get()` in a browser, or through the native
AuthenticationServices APIs. It is not reachable from a shell, from Node, or from any
process the script runs in. It signs exactly one thing — a WebAuthn assertion whose
`clientDataJSON` the browser wrote — and it will not sign anything else on the script's
behalf.

Three consequences follow, and they determine the whole design:

1. **The human's passkey can only authorize; it can never be the script's credential.** No
   amount of plumbing gets that key to sign for a cron job. The human's role is to approve
   the creation of a _second, separate_ credential that the script owns.
2. **The script's key is generated on the script's host and never leaves it.** The
   provisioning exchange carries only a public key. Nothing secret is ever in transit, in
   the human's clipboard, in a log, or in the server's database — which is a materially
   better story than "an admin generates an API key and pastes it to you."
3. **The two credentials look different in ways that matter, and the same fields mean
   different things on each.** This is the concrete case for issue #11:

|                 | Human's passkey (Apple Passwords)                           | Script's credential                    |
| --------------- | ----------------------------------------------------------- | -------------------------------------- |
| `deviceType`    | `multiDevice`                                               | `singleDevice`                         |
| `backedUp`      | `true`                                                      | `false`                                |
| `signCount`     | `0` forever — iCloud Keychain keeps no counter              | `0` by policy                          |
| `userVerified`  | `true`, **attested by a platform authenticator** (Touch ID) | `true`, **self-asserted by a program** |
| `origin`        | written by the browser — phishing-resistant                 | written by the script — proves nothing |
| Proposed `kind` | `'person'`                                                  | `'service'`                            |

Note that `signCount` is `0` on both rows, for unrelated reasons. Any deployment with Apple
passkeys already tolerates `0 → 0`, which is why the machine-credential counter policy in
`DESIGN-MACHINE-CREDENTIALS.md` §5.5 costs nothing to adopt.

## Roles and keys

```
┌─────────────────────────────┐
│ Human, in a browser         │   Passkey in Apple Passwords.
│                             │   Signs: WebAuthn assertions, browser-mediated.
│                             │   Purpose: authenticate the human, and authorize
│                             │            the creation of the script's credential.
└─────────────────────────────┘

┌─────────────────────────────┐
│ Script, headless            │   Its own key pair, born on this host.
│                             │   Signs: WebAuthn assertions (session start),
│                             │          DPoP proofs (per request, optional).
│                             │   Purpose: be the script.
└─────────────────────────────┘
```

Two credentials, one user row, distinguished by `kind`. On a Mac there is a pleasing
symmetry available: the human's key sits in Apple Passwords (Secure Enclave-protected,
synced); the script's key can sit in the _same Mac's_ Keychain (Secure Enclave,
non-synced, non-exportable). Same hardware, two credentials, different classes.

## Flow A — bootstrap token (recommended)

The minimal flow, and the one the package's existing enrollment machinery already
implements. The human hands the script a short-lived, single-use token; the script converts
it into a key it owns.

```
 Human + browser                 Server                          Script
 ───────────────                 ──────                          ──────
 1. sign in
    navigator.credentials.get() ─────►
    Touch ID / Apple Passwords
                                 verifyAuthentication()
                             ◄── session cookie

 2. "Create API credential"
    ── re-prompt: fresh assertion ──►
                                 verifyAuthentication()   ← step-up, see below
                                 issueEnrollment(userId, {
                                   credentialKind: 'service' })
                             ◄── one-time token (52 chars, 30 min)

 3. paste into .env  ─────────────────────────────────────────►  LWA_ENROLLMENT_TOKEN=…

 4.                                                              first run:
                                                                 generate key pair
                             ◄──── exchangeEnrollment(token) ────
                             ────► enrollmentSessionToken (10 min)
                             ◄──── registrationOptions() ────────
                             ────► challenge
                             ◄──── verifyRegistration(response) ─
                                 credential stored, kind='service'
                             ────► credentialId + session

 5.                                                              rewrite .env:
                                                                 drop the token,
                                                                 store key + handles
```

### Server side

Step 2, in the host's route. The important part is the step-up:

```ts
// POST /api/settings/api-credentials
const resolved = await auth.resolveSession(sessionToken);
if (!resolved) return unauthorized();

// SECURITY.md: "require a fresh passkey assertion for sensitive credential changes."
// Minting a long-lived API credential is exactly that. A live cookie is not enough.
const FRESH_MS = 2 * 60_000;
if (Date.now() - resolved.session.authenticatedAt > FRESH_MS) {
  return reauthRequired(); // client re-runs the passkey ceremony, then retries
}

const issue = await auth.issueEnrollment(resolved.user.id, {
  credentialKind: 'service', // proposed; fixes the kind on the grant row
  approvedByUserId: resolved.user.id,
});
return json({ token: issue.enrollmentToken, expiresAt: issue.expiresAt });
```

`authenticatedAt` already exists on `SessionIdentity`, so the freshness gate needs no new
machinery. Without it, a stolen session cookie mints a durable credential that outlives the
cookie — the session becomes a credential factory.

Two operational notes. `enrollmentGrantMs` defaults to 30 minutes, which is tight if the
human gets distracted between copying the token and running the script; consider a longer
duration for the service kind, or just re-issue. And the grant carries `credentialKind`, so
per `DESIGN-MACHINE-CREDENTIALS.md` §5.7 the pending-grant unique index must be scoped by
kind or this issue will revoke the human's in-flight enrollment link.

### Script side

```ts
import { enroll, MachineClient, keychainKeyStore } from '@localwebauthn/client'; // proposed

const keyStore = await keychainKeyStore({ service: 'localwebauthn-nightly-export' });

if (process.env.LWA_ENROLLMENT_TOKEN) {
  const identity = await enroll({
    baseUrl: process.env.LWA_BASE_URL,
    enrollmentToken: process.env.LWA_ENROLLMENT_TOKEN,
    keyStore, // generates the key pair in place
    label: 'nightly-export @ build-01',
  });
  await writeEnv({ ...identity, LWA_ENROLLMENT_TOKEN: undefined }); // token is now dead
}
```

`enroll` runs `exchangeEnrollment` → `registrationOptions` → build the attestation →
`verifyRegistration`, exactly as `DESIGN-MACHINE-CREDENTIALS.md` §4 describes. The
enrollment token is single-use, so a second run with the same token fails by construction;
dropping it from `.env` is hygiene, not the security boundary.

## Flow B — device authorization (better UX)

Flow A asks the human to copy a secret. For an interactive CLI, borrow the shape `gh auth
login` and `aws sso login` use: the script starts the request, the human approves it in a
browser with Touch ID, the script polls.

```
 Script                          Server                         Human + browser
 ──────                          ──────                         ───────────────
 generate key pair
 POST /provision/request ───────►
   { publicKeyCose, label }      store pending request,
                            ◄──  { requestId, userCode: "WXYZ-1234", verifyUrl }
 print the URL and code
 poll /provision/:id ───────────►  "pending"
                                                                open verifyUrl
                                                                sign in with passkey
                                                                confirm code WXYZ-1234
                                 fresh assertion required
                                 register the pending public key,
                                 kind='service'
 poll /provision/:id ───────────►  { credentialId, userHandle, … }
 write .env
```

No secret is ever copied — the human types a four-plus-four code they read off their own
terminal, which is a confirmation, not a credential. The cost is a pending-request table
with expiry and a polling endpoint, neither of which the package provides today. Flow A is
strictly less work; Flow B is strictly nicer to use. Both end in the same credential row.

## What lands in `.env`

The useful framing: **one secret, several public values.** Everything except the private key
is safe in version control, a log, or a support ticket.

```ini
# public — needed to construct an assertion, secret to nobody
LWA_BASE_URL=https://app.example.com
LWA_RP_ID=app.example.com
LWA_ORIGIN=https://api.example.com     # see kind-partitioned origins, design §5.6
LWA_CREDENTIAL_ID=k7Rz…                # base64url, chosen by the script at registration
LWA_USER_HANDLE=9fQ2…                  # base64url, 32 bytes, from options.user.id
LWA_ALG=-7                             # COSE ES256

# the one secret
LWA_PRIVATE_KEY=MIGHAgEAMBMGByqGSM49…  # base64 PKCS#8
```

Three custody options, in increasing order of how much they are worth:

| Option          | `.env` holds                                        | Notes                                                                                                                           |
| --------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Key in the file | the PKCS#8 blob                                     | Mode `0600`, gitignored. Still better than an API key: never transmitted, server holds only the public half.                    |
| macOS Keychain  | `LWA_KEY_REF=keychain:localwebauthn-nightly-export` | Zero secrets in `.env`. Access controlled by the login keychain.                                                                |
| Secure Enclave  | same key ref                                        | P-256 only, **non-exportable**. An attacker with root can _use_ the key while they hold the box; they cannot take it with them. |

On the machine where the human already keeps their passkey, the third option is available
for nothing, and it is the one that makes this materially different from a shared secret.

## Steady state

```ts
const client = new MachineClient({ baseUrl, identity, keyStore });
const report = await client.fetch('/api/reports', { method: 'POST', body });
```

Under the covers: no live session, so run `authenticationOptions` → build the assertion →
`verifyAuthentication` → hold the opaque session token; attach it and re-authenticate once
on a 401. At the default eight-hour session lifetime that is two extra round trips per
shift.

If the server route is machines-only, it asks for that explicitly — the challenge carries
the admissible kinds, per `CONSENSUS.md`:

```ts
const { options, challengeToken } = await auth.authenticationOptions({
  credentialKinds: ['service'], // proposed
});
```

And to sender-constrain the session so a leaked token is useless on its own, the script
generates a second, ephemeral key and sends its thumbprint at authentication time, then
signs a DPoP proof per request:

```http
POST /api/reports HTTP/1.1
Authorization: DPoP <session-token>
DPoP: <compact JWS over jti, htm, htu, iat, ath>
```

## What the human sees afterward

The payoff for issue #11 — an honest credential list on the account page:

```ts
await auth.listCredentials(user.id);
// [ { kind: 'person',  label: 'Apple Passwords',        deviceType: 'multiDevice',  backedUp: true  },
//   { kind: 'service', label: 'nightly-export @ build-01', deviceType: 'singleDevice', backedUp: false } ]
```

Without `kind`, the second row reads as a human with a hardware authenticator, and an audit
line saying "passkey registered, userVerified: true" implies a person was present. With it,
the row says what it is, revocation can be filtered, and middleware can refuse a
`'service'` session on a human-only route.

## A hole this flow exposes

Working the flow end to end surfaces something `DESIGN-MACHINE-CREDENTIALS.md` missed.

`registrationOptions({ sessionToken })` authorizes registering a credential from _any_ live
session. That is the intended "add another passkey" feature for a human. But the script's
session is also a live session — so **a leaked `.env` key can register a second credential
and survive revocation of the first.** Revoke the compromised key, and the attacker still
holds the spare they minted. Revocation stops being a remedy.

The design's rotation story in §7 depends on exactly this path ("authenticate with key A,
register key B, revoke A"), so the two are in direct conflict. The security-first
resolution:

- **Default: refuse session-path registration when the authorizing session's credential
  kind is non-null.** A machine session authenticates; it does not enroll.
- Rotation then goes back through a human: the person issues a fresh grant from their own
  freshly-asserted browser session, exactly as at provisioning time. Slightly more work,
  and it keeps revocation meaningful.
- A host that genuinely needs unattended rotation opts in per kind, accepting that
  revocation of one key no longer bounds the compromise.

This revises §7's claim that zero-downtime rotation is free. It is free only if you accept
that a machine credential can replicate itself.

## Revoking

```ts
// the script's key only
await auth.revokeCredential(user.id, credentialId);

// all machine access for this person, passkeys untouched
await auth.revokeUserAuthentication(user.id, { kinds: ['service'] }); // proposed

// sign the human out everywhere without stopping the nightly job
await auth.revokeUserSessions(user.id, { kinds: ['person'] }); // proposed
```

Note the kind-scoped last-credential guard from §5.4 matters here: without it, the script's
credential counts as "another active credential" and lets you revoke the human's only
passkey, locking them out while reporting success.

## Honest limits

- **The script inherits the human's authority.** A credential on the human's user row acts
  as that human. Deactivating them stops the script; their permissions are the script's
  permissions. For anything long-lived or broadly scoped, give the script its own service
  user instead and let the human authorize _that_ enrollment.
- **`userVerified: true` from the script means a program set a bit.** Never render it as
  human presence, and never let a `'service'` credential satisfy a human-presence check.
- **The human approved a credential, not a scope.** Authorization stays with the host; the
  package tells it `kind` and `credentialId` and nothing more.
- **A `.env` private key is as safe as the file.** Mode `0600` and a gitignore entry are
  the floor; the Keychain and Secure Enclave options above are what actually change the
  threat model.
