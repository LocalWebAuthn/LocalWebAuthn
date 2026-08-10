# Design: machine credentials (API clients) — issue #11

> **Superseded design note.** Written before the implementation and not updated since;
> where it disagrees with [`docs/API-AUTH.org`](../../API-AUTH.org), that document is
> right. See [the history index](README.md) for what each of these was.

Status: proposal. Targets [#11](https://github.com/LocalWebAuthn/LocalWebAuthn/issues/11).

## 1. Summary

A WebAuthn assertion is a signature over `authenticatorData ‖ SHA-256(clientDataJSON)`.
Producing one requires a private key and about sixty lines of code. It does not require a
browser, a human, or a biometric. This package already verifies such assertions — the
demo suite produces roughly forty of them per run against a software authenticator — so a
CLI or a daemon can authenticate against `verifyAuthentication` today.

What the package cannot do is _record_ that it did, or make policy depend on it. This
design adds that, and does it by moving every machine-relevant fact onto a row the server
owns rather than onto a field the client asserts.

Concretely:

- A nullable, host-defined `kind` on the credential, fixed **before the client ever sees
  a challenge** — from the enrollment grant, or from the host's call to
  `registrationOptions`; never from the verification request body.
- Authentication challenges carry the set of credential kinds they will accept, so a
  route that means "machines only" is enforced by the package rather than by each host.
- `kind` reported on the assertion result and carried on `SessionIdentity`, so
  authorization can key on it without a second lookup.
- Kind filters on the bulk revocation methods, so signing a person out of their devices
  does not kill their nightly export job.
- A companion `@localwebauthn/client` package that builds the assertion bytes and holds
  its key in a pluggable store (file, OS keychain, TPM, cloud KMS, PKCS#11).

This changes a documented non-goal. `docs/RATIONALE.md` lists "machine-to-machine
authentication" and `SECURITY.md` lists "API-token authentication" as things the package
does not provide. The reasoning behind those entries — _policy varies materially between
applications, so keep it outside the package_ — survives intact: authorization, scopes,
and rate limits remain the host's. What changes is the claim that a machine client cannot
authenticate at all, which is already false in the code as shipped.

## 2. What an assertion proves, and what it does not

### 2.1 The claims this design rejects

The received wisdom on this subject is that passkeys are for humans in browsers and
cannot serve machines. Stated carefully, the specific claims are these, and each is
either false or a non sequitur.

> _"Passkeys require a user interface and an authenticator (like a phone or hardware
> key)."_

"Authenticator" in WebAuthn is a **role**, not a device class. Its obligations are: hold
a key pair, emit a 37-byte `authenticatorData`, and sign. A function discharges all
three. The W3C specification standardises a _Virtual Authenticator_ precisely so that
software can occupy the role; Chrome exposes it as the CDP `WebAuthn` domain, which this
repository already drives in `examples/demo/e2e/lifecycle.spec.ts:13`.

> _"…to approve a cryptographic challenge via biometrics or a PIN."_

User verification is bit 2 of `authenticatorData[32]`. WebAuthn §7.2 requires a relying
party that demanded UV to check that the bit is set. It does not — and could not —
require that a human was involved. What arrives at the server is a bit, not a fingerprint.

> _"…making them unusable for headless JavaScript servers communicating directly with
> external APIs."_

The demo suite authenticates from headless Chrome, with no human and no hardware, on
every CI run. `@simplewebauthn/server` verifies those assertions and is correct to.

> _"Continue using client secrets … because servers cannot prompt a user for a biometric
> touch."_

The conclusion does not follow from the premise. "No human is present" is an argument
against _user verification_, not an argument for a _shared secret_. It argues for exactly
the opposite: with no human to be phished, the only remaining question is whether the
long-lived credential is symmetric or asymmetric, and asymmetric wins on every axis.

> _"Use … signed JWTs, or mutual TLS (mTLS)."_

`private_key_jwt` is structurally the same construction: the client signs a
server-supplied nonce inside an audience-bound blob with a key the server knows only by
its public half. If `private_key_jwt` is sound for machine-to-machine, so is a WebAuthn
assertion. They differ in encoding, not in security properties.

What is true, and worth stating fairly: browser-mediated origin binding is real, and it
is what makes a passkey phishing-resistant. The browser writes `origin` into
`clientDataJSON`, and the browser is software the _user_ trusts and the attacker does not
control. That is a protection delivered **to** the key holder against third parties. It
was never a constraint **on** the key holder. Reading it as one is the error that produces
the claims above.

### 2.2 The principle

> **A signature proves possession of a key. Nothing else in the assertion is evidence.**
>
> Every field the signer controls — `origin`, the UP and UV flags, the signature counter,
> the AAGUID, the extensions — is a claim the signer makes about itself. A signer willing
> to lie will lie, and no verification step can distinguish a truthful claim from a
> fabricated one. Any security property that rests on the key holder having behaved in a
> particular way is not a property at all.

Applied to the split between what the client sends and what the server holds:

| Fact                                           | Who chooses it | Is it a control?   |
| ---------------------------------------------- | -------------- | ------------------ |
| Challenge freshness and single use             | server         | **yes**            |
| Signature verifies under the stored public key | mathematics    | **yes**            |
| Credential ↔ user binding                      | server row     | **yes**            |
| Revocation state, user `active`                | server row     | **yes**            |
| Credential `kind` (this design)                | server row     | **yes**            |
| `clientDataJSON.origin`                        | client         | no — self-asserted |
| UV / UP flags                                  | client         | no — self-asserted |
| Signature counter                              | client         | no — self-asserted |
| `rpIdHash`                                     | client         | no — self-asserted |
| AAGUID, transports, BE/BS bits                 | client         | no — self-asserted |

For a browser passkey the right-hand column is populated by a browser and a certified
authenticator, which is why those fields carry meaning there. For a machine credential
they carry none. The design therefore does not attempt to recover the lost guarantees. It
replaces them with facts in the left column, which a hostile key holder cannot touch.

This is also the strongest argument for issue #11's request. The reason `kind` must be a
server-owned column — rather than, say, a distinctive AAGUID or a reserved origin string
the client writes — is that a server-owned column is the only kind of fact that survives
the key holder turning hostile.

### 2.3 What survives, and what is lost, for a machine client

Unchanged and still real:

- **Anti-replay.** Every authentication consumes a fresh, single-use, server-issued
  challenge with a five-minute expiry. This is strictly stronger than a signature counter
  and it is the control people usually believe the counter provides.
- **No shared secret.** The server stores a public key. A database disclosure yields
  nothing that authenticates.
- **Nothing replayable on the wire.** The long-lived secret never leaves the client. Only
  a signature over a nonce crosses the network.
- **Per-credential revocation** with an existing audit event.
- **Hardware-backed keys.** The signing key can live in a TPM, a Secure Enclave, a cloud
  KMS, or a PKCS#11 token. This is the step change over an API key in an environment
  variable, and it is the reason to do this at all.

Genuinely lost:

- **Phishing resistance.** There is no human judgement to attack, so there is no phishing
  surface. A control that mitigates a non-existent attack costs nothing when removed.
- **Human presence.** `userVerified: true` from a machine client means "a program set a
  bit." The package must never surface it as evidence of a person. This is exactly the
  "meaning" complaint in issue #11.
- **Clone detection via the counter.** See §5.5 — it was theatre for a key in a file.

## 3. What the client stores

The complete client-side state, answering the question directly.

**Secret — one item:**

1. **The private key.** ES256 (P-256, COSE alg `-7`) or Ed25519 (COSE alg `-8`).
   Non-exportable wherever the platform allows it.

**Non-secret, but required to construct an assertion:**

2. **Credential ID** — 32 random bytes chosen by the client at registration. Echoed as
   `id` / `rawId`; the server's primary key for the row.
3. **RP ID** — the string, or its precomputed SHA-256 (`authenticatorData[0..32]`).
4. **User handle** — the 32 bytes from `options.user.id` at registration. This package
   requires `response.userHandle` and compares it against `AuthUser.webAuthnUserHandle`,
   so it is not optional.
5. **Origin string** — the exact value to place in `clientDataJSON.origin`. Must be
   accepted by the server's expected-origin set (see §5.6).
6. **COSE algorithm** — so the client signs with the curve and hash the stored public key
   expects.

**Policy:**

7. **Signature counter** — a `uint32`. Constant `0` under the recommended policy, in
   which case there is nothing to persist. See §5.5.
8. **Base URL** of the API.

That is the whole of it: one key plus roughly two hundred bytes of metadata. Items 2–6 are
public and can sit in a world-readable config file next to the key handle.

Not stored, because it is not needed after bootstrap: the enrollment token (single-use,
consumed during registration) and the AAGUID (used only inside the registration
attestation).

## 4. The bytes

`authenticatorData` for an assertion is 37 bytes — no attested credential data, no
extensions:

```
[0..32)   rpIdHash    SHA-256(rpId)
[32]      flags       0x01 UP | 0x04 UV   (AT and ED clear)
[33..37)  signCount   uint32, big-endian
```

`clientDataJSON` is UTF-8 JSON. The relying party hashes the bytes it received, so the
exact serialization is the client's business as long as the fields parse:

```json
{
  "type": "webauthn.get",
  "challenge": "<the server's base64url string, verbatim>",
  "origin": "<origin>",
  "crossOrigin": false
}
```

The signature is over the concatenation:

```ts
const clientData = utf8(
  JSON.stringify({ type: 'webauthn.get', challenge, origin, crossOrigin: false }),
);

const authData = new Uint8Array(37);
authData.set(rpIdHash, 0);
authData[32] = 0x01 | 0x04; // UP | UV
new DataView(authData.buffer).setUint32(33, signCount, false); // big-endian

const signed = concat(authData, sha256(clientData));
const signature = await keyStore.sign(signed);

return {
  id: b64u(credentialId),
  rawId: b64u(credentialId),
  type: 'public-key',
  clientExtensionResults: {},
  response: {
    clientDataJSON: b64u(clientData),
    authenticatorData: b64u(authData),
    signature: b64u(signature),
    userHandle: b64u(userHandle),
  },
};
```

That object is a valid `AuthenticationResponseJSON` and goes straight to
`verifyAuthentication`.

Registration is the same idea with three additions: `type` is `"webauthn.create"`, the AT
flag (`0x40`) is set and `attestedCredentialData` is appended
(`aaguid(16) ‖ credIdLen(2, BE) ‖ credentialId ‖ COSE public key`), and the whole thing is
wrapped in a CBOR attestation object `{ fmt: "none", attStmt: {}, authData }`. With
`fmt: "none"` the CBOR is nearly constant-shaped; a hand-rolled encoder is about forty
lines.

Three implementation notes that cost people a day each:

- **ES256 signatures must be ASN.1 DER** `SEQUENCE { INTEGER r, INTEGER s }`. WebCrypto's
  `ECDSA` sign returns raw `r ‖ s`. Convert, or the signature fails verification with no
  useful error. Ed25519 signatures are raw 64 bytes and need no conversion, which is one
  reason to prefer `-8` where the key store supports it.
- **BE/BS flags must be consistent.** `BS` (0x10) may not be set unless `BE` (0x08) is;
  SimpleWebAuthn rejects the invalid combination. A single-host machine credential should
  emit `BE=0, BS=0`, which the server records as `deviceType: 'singleDevice',
backedUp: false`. Note that this is precisely the row issue #11 says reads as "a human
  with a hardware authenticator" — and that setting `BE=1, BS=1` for a replicated key
  would read as an iCloud-synced passkey instead. Neither existing value is honest, which
  is the argument for a new column rather than reinterpreting an old one.
- **Echo the challenge string verbatim.** `generateAuthenticationOptions` returns
  base64url; re-encoding it will not round-trip identically.

## 5. Server-side design

### 5.1 `kind` is fixed before the client sees a challenge

Issue #11 proposes `verifyRegistration(..., { credentialKind })`. That is the right column
in the wrong place. `verifyRegistration` is called from an HTTP handler holding a request
the client composed; a host that passes a body field straight through hands the client
control of its own classification, and per §2.2 a client-chosen field is not a control.

Instead, the kind is decided by whoever authorized the registration, at the moment they
authorized it, and is durable from that moment:

- **Grant path.** `issueEnrollment(userId, { credentialKind: 'service' })` writes the kind
  on the grant row. The administrator issuing the bootstrap token decides what the token
  may create. `resolveEnrollmentSession` returns it, and `completeRegistration` copies it
  onto the credential. The audit trail shows "a grant for a service credential was issued"
  before the credential exists.
- **Session path** (an authenticated client adding another credential — the rotation
  path). There is no grant, so the host passes `registrationOptions({ ...,
credentialKind })`, which records it on the **challenge** row. `verifyRegistration`
  reads it from there.

In both cases the kind is on a server row before the client receives its challenge, and
`verifyRegistration` takes no `credentialKind` input at all. If the challenge came from a
grant of kind X, the credential is kind X; there is no code path that can write anything
else.

Recommended vocabulary — opaque to the package, as the issue asks: `'person'`,
`'service'`, `null` for existing rows and hosts that never set one.

### 5.2 Challenge-scoped kinds

A host that mounts a browser login route and a machine login route calls the same
`verifyAuthentication` from both. Nothing stops a browser passkey authenticating on the
machine route or a service key on the browser route, and if the two routes apply different
policy the confusion is the host's to prevent — in every host, identically.

So put the constraint on the challenge, which is a server-owned row:

```ts
authenticationOptions({ credentialKinds: ['service'] });
```

The allowed set is written to `localwebauthn_challenges.allowed_credential_kinds` (JSON
array; `NULL` means any). `verifyAuthentication` refuses a credential whose kind is not in
the set, with the existing `authentication_failed` 401. `null` is a legal member of the
array so hosts can express "unclassified credentials only" during migration.

This is a real control, and cheaply so: the ceremony's admissible credential kinds are
chosen by the server before the client sees the challenge, and the credential's kind is a
row keyed by the credential ID that the signature already binds.

### 5.3 `kind` on the assertion result and the session

Issue #11's first "more than a label" item. Without it, a service credential produces a
session indistinguishable from a person's, and every human-only route is quietly open to
the fleet.

- `AuthenticationVerificationResult.credentialKind: string | null`
- `RegistrationVerificationResult.credentialKind: string | null`
- `SessionIdentity.credentialKind: string | null`
- `LocalWebAuthnEvent` credential and session events gain `credentialKind`

`SQL.selectSession` already joins `localwebauthn_credentials`, so carrying the kind
through `resolveSession` is one extra selected column and no extra query. Host middleware
then reads it directly:

```ts
const resolved = await auth.resolveSession(token);
if (resolved?.session.credentialKind === 'service' && route.requiresPerson) return forbidden();
```

Kind is immutable after registration, so there is no staleness question.

### 5.4 Kind-filtered revocation

Issue #11's second item.

```ts
revokeUserAuthentication(userId, { kinds?: (string | null)[] })
revokeUserSessions(userId, { exceptSessionToken?, kinds?: (string | null)[] })
revokePendingEnrollments(userId, { credentialKind? })
listCredentials(userId, { includeRevoked?, kinds? })
```

Omitting `kinds` keeps today's behaviour exactly.

**One behaviour change, and it needs a decision.** The last-credential guard currently
counts _all_ the user's active credentials. Once a person has both a phone and a
deployment key, that guard lets you revoke their last human passkey — the deployment key
satisfies "more than one active" — and lock them out of the interactive path while
reporting success. Scoping the guard to the credential's own kind fixes it:

```sql
UPDATE localwebauthn_credentials AS target
   SET revoked_at = ?
 WHERE id = ? AND user_id = ? AND revoked_at IS NULL
   AND (? = 1 OR EXISTS (
         SELECT 1 FROM localwebauthn_credentials AS other
          WHERE other.user_id = ? AND other.id <> ? AND other.revoked_at IS NULL
            AND COALESCE(other.kind, '') = COALESCE(target.kind, '')))
```

The change is monotone: it is never weaker than today, and for any user whose credentials
all share one kind — including every existing deployment, where all kinds are `NULL` — the
behaviour is byte-identical. It is stricter in exactly one new case: revoking the last
credential of a kind now requires the explicit `allowLastCredential: true` the API already
provides, which is what a deployment pipeline decommissioning a key would pass anyway.

`SQL.isLastActiveCredential` takes the same predicate. PostgreSQL's `lockUserCredentials`
can keep locking all of the user's active rows — a superset of the same-kind set is still
correct and keeps the deterministic `ORDER BY id` that prevents deadlock.

### 5.5 Signature counters

A hostile key holder picks any counter they like, so the counter is not a control against
them. It detects _cloning_ — a key copied while the original keeps being used — and only
that.

For a machine credential the recommendation is a **constant zero**, which WebAuthn permits
and this package already accepts (`0 → 0` passes; the rule lives in `service.ts:524` and
`SQL.advanceCredentialCounter`). Three reasons:

1. Replay, the attack people think the counter stops, is already defeated by the
   single-use server challenge — a strictly stronger, server-owned control.
2. Clone detection is meaningless for a key in a file, impossible for a key shared across
   a fleet or held in a KMS, and unnecessary for a key in a TPM that cannot be cloned.
3. The failure mode is operationally vicious for unattended systems. Restore a host from a
   backup taken before the last authentication and the counter goes backwards; the
   credential is rejected permanently and the machine needs re-enrollment at 3 a.m.

A single-instance client with durable storage _may_ keep a real monotonic counter and get
genuine clone detection — a copied key produces a stale counter and a rejection, and the
rejection is a signal worth alerting on. It must `fsync` before sending. Gaps are fine;
going backwards is fatal.

An explicit `counterPolicy: 'strict' | 'none'` column is **not proposed for the first
cut**. The existing rule already handles the mechanics correctly, including refusing to
let a strict credential silently degrade to zero. The only thing a policy column adds is
honesty in the row — telling an operator whether `counter = 0` means "hardware without a
counter" or "software that opted out" — which is worth revisiting once `kind` exists and
can already answer most of that question.

### 5.6 Optional: per-kind expected origins

`clientDataJSON.origin` from a software client is self-asserted and proves nothing. It
does not follow that the package should stop checking it: WebAuthn §7.2 step 9 requires
the check, and dropping it would put the package out of conformance for no gain.

The optional refinement is to partition the allowlist by kind, so a service credential
writes `https://api.example.com` and the browser allowlist never contains that value:

```ts
credentialKinds: {
  service: {
    expectedOrigins: 'https://api.example.com';
  }
}
```

Be precise about what this buys. It is **not** a control against a hostile key holder — a
holder of the service key simply writes the service origin. It is a control against _the
host's own routing mistakes_: a service credential becomes structurally incapable of
producing an assertion the browser-facing path accepts, and the recorded origin in the
audit trail is honest about which path a request arrived on. That is the same argument the
package already makes for shipping `authCookieNames` and `cookieAttributes` rather than
letting each host re-derive them.

§5.2's challenge-scoped kinds cover the same confusion more directly and with a
server-owned field, so this is a nice-to-have, not a requirement.

### 5.7 Schema (version 2)

```sql
ALTER TABLE localwebauthn_credentials       ADD COLUMN kind TEXT;
ALTER TABLE localwebauthn_enrollment_grants ADD COLUMN credential_kind TEXT;
ALTER TABLE localwebauthn_challenges        ADD COLUMN credential_kind TEXT;
ALTER TABLE localwebauthn_challenges        ADD COLUMN allowed_credential_kinds TEXT;

CREATE INDEX localwebauthn_credential_kind_idx
  ON localwebauthn_credentials(user_id, kind, revoked_at);

DROP INDEX localwebauthn_active_grant_user_idx;
CREATE UNIQUE INDEX localwebauthn_active_grant_user_idx
  ON localwebauthn_enrollment_grants(user_id, COALESCE(credential_kind, ''))
  WHERE completed_at IS NULL AND revoked_at IS NULL;
```

`COALESCE` in the index expression is required: `NULL`s are distinct in a unique index on
both SQLite and PostgreSQL, so indexing the bare column would silently drop today's
one-pending-grant-per-user invariant for the default kind. `replaceEnrollmentGrant` and
`SQL.revokePendingGrants` become kind-scoped to match — issuing a deployment-key grant
must not revoke a person's in-flight enrollment link.

Two `credential_kind` columns on `challenges` look redundant but are not: one is the kind
this registration will _create_ (§5.1, registration challenges), the other is the set of
kinds this authentication will _accept_ (§5.2, authentication challenges). The existing
`CHECK` that non-registration challenges carry no authorization fields extends naturally:
`credential_kind` is registration-only, `allowed_credential_kinds` authentication-only.

**There is no migration machinery yet.** `LOCALWEBAUTHN_SCHEMA_VERSION` is 1 and
`localWebAuthnMigrationStatements()` runs `CREATE TABLE IF NOT EXISTS` plus a version
insert, which will not add a column to an existing table. This change needs a versioned
statement list applied for `version > current`, in all three adapters. That is a
prerequisite, not an afterthought, and it is worth building carefully since it is the
mechanism every future schema change will use.

### 5.8 API and store deltas

Types:

```ts
type Credential = { /* … */ kind: string | null };
type EnrollmentGrantRecord = { /* … */ credentialKind: string | null };
type EnrollmentSession = { /* … */ credentialKind: string | null };
type ChallengeRecord = {
  /* … */ credentialKind: string | null;
  allowedCredentialKinds: (string | null)[] | null;
};
type SessionIdentity = { /* … */ credentialKind: string | null };
```

Service methods. Three take a second positional argument today; each becomes a union with
an options object so existing call sites keep compiling:

```ts
issueEnrollment(userId, approvedByUserId?: string)
issueEnrollment(userId, options?: { approvedByUserId?: string; credentialKind?: string })

listCredentials(userId, includeRevoked?: boolean)
listCredentials(userId, options?: { includeRevoked?: boolean; kinds?: (string | null)[] })

registrationOptions({ enrollmentSessionToken?, sessionToken?, credentialKind? })
authenticationOptions({ credentialKinds?: (string | null)[] } = {})
revokeUserAuthentication(userId, options?: { kinds?: (string | null)[] })
```

Store contract: no new methods. The existing ones carry additional columns, plus the
kind-scoped predicates in `revokePendingGrants`, `revokeCredential`,
`isLastActiveCredential`, `revokeUserCredentials`, and `revokeLiveUserSessions`. Custom
store implementers get a `MIGRATING.md` section; the changes are mechanical.

`#credentialLabel` should stop defaulting a `kind: 'service'` credential to "Device
passkey". Defaulting to the kind itself, or requiring an explicit label for non-null
kinds, keeps the credential list honest — which is the whole point of the issue.

## 6. Client architecture

A new package, `@localwebauthn/client`, symmetric with `@localwebauthn/browser`.

```ts
// Bootstrap — once, at deploy time.
const identity = await enroll({
  baseUrl: 'https://api.example.com',
  enrollmentToken, // from issueEnrollment(), handed over by the deploy system
  keyStore,
  label: 'nightly-export @ i-0abc123',
});
// → generates the key pair inside keyStore, registers, returns
//   { credentialId, userHandle, rpId, origin, algorithm } — all public, safe to write to disk

// Steady state.
const client = new MachineClient({ baseUrl, identity, keyStore });
const response = await client.fetch('/api/reports', { method: 'POST', body });
```

`MachineClient.fetch` authenticates lazily: with no live session it runs
options → assert → verify, keeps the opaque session token in memory, attaches it as a
bearer, and re-authenticates once on a 401. At the default eight-hour absolute session
lifetime that is two extra round trips per shift — amortised to nothing — and the
long-lived secret still never crosses the wire. Session tokens are held in memory only;
losing them on restart costs one handshake.

The one interface that matters:

```ts
type MachineKeyStore = {
  algorithm: -7 | -8; // ES256 | EdDSA
  publicKeyCose(): Promise<Uint8Array>; // COSE_Key, registration only
  sign(data: Uint8Array): Promise<Uint8Array>; // DER for -7, raw for -8
};
```

Nothing in the client assumes the key is in memory, which is what lets the interesting
backends plug in:

| Backend                                   | Key exportable? | Notes                                                                               |
| ----------------------------------------- | --------------- | ----------------------------------------------------------------------------------- |
| File, mode 0600                           | yes             | Baseline. Still strictly better than an API key on the wire.                        |
| OS keychain / DPAPI / kernel keyring      | no, in practice | Cheap upgrade, no hardware needed.                                                  |
| TPM 2.0, Secure Enclave                   | **no**          | Key cannot be copied off the host.                                                  |
| AWS/GCP/Azure KMS                         | **no**          | Every signature is an IAM-authorized, separately audited operation.                 |
| PKCS#11, YubiHSM, FIDO2 key over CTAP-HID | **no**          | A server with a hardware token in a USB port is a perfectly ordinary authenticator. |

The last three rows are the argument for this whole design. An API key is a string that
can be read out of a process, a log, a heap dump, or a backup. A TPM-resident P-256 key
cannot be read out of anything; an attacker with root gets to _use_ it until the host is
cleaned and the credential revoked, which is a materially smaller blast radius and a
detectable one.

Also shipped: a `--dry-run` mode that prints the constructed `authenticatorData`,
`clientDataJSON`, and signature, because when this breaks it breaks with
"authentication_failed" and no detail, by design.

## 7. Lifecycle

**Bootstrap.** `issueEnrollment(userId, { credentialKind: 'service' })` → the token goes
to the deployment system's secret store (not to email — the confidential-channel
requirement in `SECURITY.md` still applies, but the channel is a secrets manager) → the
instance exchanges it, generates a key in its key store, registers, and holds a
credential.

Note the shape of that: **a bearer secret that is single-use and expires in thirty minutes
converts into a non-bearer credential the machine holds for its lifetime.** That is the
substantive difference from an API key, which is a bearer secret that lives forever and is
replayed on every request. It is the SPIFFE/workload-identity bootstrap pattern,
implemented with primitives this package already has.

**Use.** Authenticate, hold a session, re-authenticate on expiry.

**Step up.** For a destructive or high-value operation, require a fresh assertion rather
than the session — the machine analogue of `SECURITY.md`'s "require a fresh passkey
assertion for recovery and sensitive credential changes." No new machinery; call
`authenticationOptions` / `verifyAuthentication` again and check the resulting
`authenticatedAt`.

**Rotate.** This already works and is worth noticing: the client authenticates with key A,
uses that session to authorize registration of key B via `registrationOptions({
sessionToken })`, then revokes A. Two valid credentials overlap for as long as the rollout
needs, and there is never a window where a secret is valid in two places under one name.
Shared-secret rotation cannot do this without dual-secret support on both sides.

**Revoke.** `revokeCredential(userId, credentialId)` kills one instance's key and its
sessions, leaving the rest of the fleet running. `revokeUserAuthentication(userId,
{ kinds: ['service'] })` kills all machine access for that identity without touching the
person's passkeys.

## 8. Threat model, honestly

|                               | Shared API key            | Machine passkey             | Browser passkey           |
| ----------------------------- | ------------------------- | --------------------------- | ------------------------- |
| Server stores a secret        | yes                       | **no**                      | no                        |
| Replayable secret on the wire | yes, every request        | **no**                      | no                        |
| Replay defeated by            | TLS only                  | **server challenge**        | server challenge          |
| Key can be hardware-bound     | no                        | **yes**                     | yes                       |
| Revocation granularity        | per key, if you bothered  | **per credential**          | per credential            |
| Zero-downtime rotation        | needs dual-secret support | **built in**                | built in                  |
| Compromise detectable         | no                        | counter, if strict          | counter                   |
| Phishing resistance           | n/a                       | n/a (no human)              | **yes**                   |
| Human presence                | n/a                       | **claimed, not proven**     | attested by authenticator |
| Origin binding                | n/a                       | **self-asserted, no value** | browser-asserted          |

The three cells that matter: a machine passkey is unambiguously better than an API key on
the first six rows, and the three rows where a browser passkey wins are rows where either
no human exists to protect or the property was never available to a machine under any
scheme. `private_key_jwt` and mTLS land in the same column as the machine passkey; the
argument for using WebAuthn instead is not cryptographic superiority but that this host
already runs one credential store, one revocation path, and one audit trail, and does not
want a second of each.

The residual risk is real and should be written down: **anyone who can use the private key
is the machine.** That is also true of an API key, of a `private_key_jwt` key, and of an
mTLS client certificate. The mitigations are the ordinary ones — hardware-bind the key,
scope the identity narrowly, keep the credential list short and readable, alert on
`credential.authenticated` from an unexpected source — and issue #11's column is what makes
the third and fourth of those possible.

## 9. Fleet topology — the open question

Two workable shapes, and the choice interacts with the grant uniqueness index in §5.7.

**One workload identity per instance.** Each replica gets its own user row
(`svc-export/i-0abc123`) and its own credential. Per-instance revocation, per-instance
audit, and strict counters all work, because each key is used by exactly one process.
Grant uniqueness is per user, so concurrent bootstraps do not collide. The cost is user
rows that churn with autoscaling and a `getUser` that must serve them.

**One service user, one credential shared by the fleet.** Simple, stable, and matches
issue #11's framing ("one user may legitimately have both a phone and a deployment key").
Requires `counter = 0` (§5.5), gives up per-instance attribution, and — the sharp edge —
**collides with the one-pending-grant-per-`(user, kind)` index whenever two instances
bootstrap at once.**

Neither is obviously right, and the second's collision is the thing to decide. The
invariant that index enforces protects _invitation delivery_: a second invite email must
not leave two live links. A machine bootstrap has no such channel and no such hazard, so
relaxing it for kinded grants is defensible — but doing it by hard-coding a kind name into
a `WHERE` clause would put a vocabulary into a package that promises to keep `kind`
opaque. The alternative, splitting `replaceEnrollmentGrant` into an explicit
"replace" and a "add without replacing", loses the index as a safety net on D1, which
cannot open a transaction and relies on that unique index to make a concurrent
double-issue fail. Recommendation: ship per-instance identities first, and revisit if the
churn proves unworkable.

## 10. What stays out

- **Authorization.** Scopes, roles, and what a machine may call remain the host's, keyed
  on `credentialKind` and `credentialId`. This is what the `docs/RATIONALE.md` non-goal
  was protecting and it is not affected.
- **Rate limiting.** `authenticationOptions` is unauthenticated and writes a row; a client
  in a tight retry loop is a self-DoS. Host responsibility, as today, plus exponential
  backoff in the client library.
- **Attestation policy.** A software authenticator's attestation is `none` and its AAGUID
  is whatever it says. Per §2.2 there is nothing to verify.
- **Credential expiry.** Machine keys should rotate on a schedule, but an expiry column is
  a second lifecycle rule and belongs in a later change, if at all — the host can enforce
  it from `createdAt` today.

## 11. Phasing

1. **Versioned migrations.** Prerequisite for everything else (§5.7).
2. **`kind`, end to end.** Column, grant/challenge plumbing, `listCredentials` filter,
   result and `SessionIdentity` fields, events. This alone closes issue #11 including both
   of its stretch items.
3. **Challenge-scoped kinds** (§5.2) and kind-filtered revocation (§5.4), including the
   last-credential guard decision.
4. **`@localwebauthn/client`** plus a worked example under `examples/`, with the same
   conformance treatment the stores get.
5. **Optional:** per-kind origins (§5.6), per-kind session durations, `counterPolicy`.

Steps 1–3 are additive to the service API and byte-identical in behaviour for any
deployment that never sets a kind. Step 3's guard change is the single exception, and it
is stricter rather than looser.

## 12. Decisions needed

1. **Fleet topology** (§9) — per-instance identities, or one shared service credential and
   a relaxed grant index?
2. **Last-credential guard** (§5.4) — scope it to the credential's own kind? Recommended,
   monotone, but it is the one change to existing behaviour.
3. **Overload or major bump** (§5.8) — union-typed second arguments on three methods, or
   accept a breaking change and take the clean options objects?
4. **Is `@localwebauthn/client` in scope for this repository**, or does the package ship
   only the server-side `kind` support and document the eighty lines of §4 for hosts to
   implement? The narrower answer closes issue #11; the wider one is what makes the
   feature usable without every adopter rediscovering the DER encoding.
