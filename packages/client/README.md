# @localwebauthn/client

A WebAuthn authenticator in software, for programs that have no browser and no human.

Install this **only** if your deployment issues API credentials. A server operator never
needs it, and a browser application never needs it either — `@localwebauthn/browser` drives
the platform authenticator for people.

```console
npm install @localwebauthn/client
```

## What it is for

A WebAuthn assertion is a signature over `authenticatorData ‖ SHA-256(clientDataJSON)`.
Producing one requires a private key and about sixty lines of code — not a browser, not a
biometric, not a human. So a nightly export script can authenticate with the same mechanism
a person's passkey uses, and the server verifies it through the same code path.

This package is that key holder: the ceremony construction, the two-line credential file, and
[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) DPoP proofs.

## The script side, in full

```ts
import {
  importKeyStore,
  MachineClient,
  parseCredentialFile,
  parseCredentialPayload,
} from '@localwebauthn/client';
import { readFile } from 'node:fs/promises';

const file = parseCredentialFile(await readFile('.env', 'utf8'));
if (!file) {
  throw new Error('No LWA_CREDENTIAL / LWA_CREDENTIAL_KEY pair.');
}
const payload = parseCredentialPayload(file.payload);
const client = new MachineClient({
  payload,
  keyStore: await importKeyStore(file.key, payload.alg),
});

await client.authenticate(); // one full WebAuthn ceremony, in software
const me = await client.fetch('/api/machine/v1/whoami'); // DPoP proof per request
```

`authenticate()` runs the ceremony and receives an ordinary session token. Every request
after it carries a DPoP proof signed by the **same** key, so a captured session token is not
enough on its own. `MachineClient` retains the server's latest `DPoP-Nonce` and retries once
when challenged, and re-authenticates on `401`.

## The credential file

Two lines: public metadata as JSON, private key as base64.

```sh
# nightly export -- created 2026-08-08T21:00:00.000Z
LWA_CREDENTIAL='{"v":1,"baseUrl":"https://app.example.com","rpId":"app.example.com", ... }'
LWA_CREDENTIAL_KEY=MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...
```

One piece of private key material, in one place. `formatCredentialFile` writes it (from the
browser page that generated the key), `parseCredentialFile` reads it, and
`isKeystoreReference` recognises a `keystore:` value for deployments that keep the key in a
platform store rather than the file.

## Lower-level pieces

Use these when building the mint page, or when debugging a rejected assertion:

| Export                                         | Purpose                                       |
| ---------------------------------------------- | --------------------------------------------- |
| `generateKeyStore(ES256 \| EDDSA)`             | a new key pair, with `exportPrivateKey()`     |
| `importKeyStore(key, alg)`                     | reopen one from a credential file             |
| `createRegistrationResponse({ ... })`          | an attestation the server will accept         |
| `createAssertionResponse({ ... })`             | a sign-in assertion                           |
| `createDpopProof({ ... })`                     | one per-request proof                         |
| `formatCredentialFile` / `parseCredentialFile` | the two-line `.env`                           |
| `rawSignatureToDer`                            | WebCrypto returns raw r‖s; WebAuthn wants DER |

Both algorithms work end to end: ES256 (COSE `-7`, DER signatures) and Ed25519 (COSE `-8`,
raw 64-byte signatures).

## What the server sees

Nothing it can mistake for a person. A credential minted this way carries a host-declared
`kind`, and the server treats `userVerified`, `origin`, the backup flags and the signature
counter as claims the signer makes about itself — because a key holder can set any of them.
`kind` is the only class fact it cannot forge.

The counter stays at `0` deliberately: a strictly increasing counter would make concurrent
sessions from one credential contend on a single compare-and-swap, and unlimited concurrent
sessions is the point. (Apple's passkeys report `0` forever too.)

## More

- The design in full, every byte of both flows, and key custody options from a file to a TPM:
  [docs/API-AUTH.org](../../docs/API-AUTH.org).
- A runnable client, which prints everything it constructs under `--dry-run`:
  [examples/demo/scripts/api-client.ts](../../examples/demo/scripts/api-client.ts).
- The server side of this: [`@localwebauthn/server`](../server).
