/**
 * A headless API client, authenticating with a Passkey held in a `.env` file.
 *
 * ```sh
 * npm run api-demo --workspace @localwebauthn/demo -- ./nightly-export.env
 * npm run api-demo --workspace @localwebauthn/demo -- ./nightly-export.env --dry-run
 * ```
 *
 * There is no browser here, no human, and no biometric — only a private key and
 * a signature over a server-issued challenge. `--dry-run` prints the constructed
 * `clientDataJSON`, `authenticatorData` and signature, because when this breaks
 * it breaks as a bare `authentication_failed` with no detail, by design.
 */

import {
  createAssertionResponse,
  createDpopProof,
  decodeBase64Url,
  importKeyStore,
  isKeystoreReference,
  MachineClient,
  MachineClientError,
  parseCredentialFile,
  parseCredentialPayload,
} from '@localwebauthn/client';
import { readFile } from 'node:fs/promises';

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

const positional = process.argv.slice(2).filter((argument) => !argument.startsWith('--'));
const flags = new Set(process.argv.slice(2).filter((argument) => argument.startsWith('--')));
const path = positional[0] ?? '.env';

const text = await readFile(path, 'utf8').catch(() => fail(`Cannot read ${path}`));
const file = parseCredentialFile(text);
if (!file) {
  fail(`${path} has no LWA_CREDENTIAL / LWA_CREDENTIAL_KEY pair.`);
}
if (isKeystoreReference(file.key)) {
  fail(
    `${path} points at ${file.key}, which this demo cannot open.\n` +
      'Keystore backends need platform bindings; see docs/API-AUTH.org, Key Custody.',
  );
}

const payload = parseCredentialPayload(file.payload);
const keyStore = await importKeyStore(file.key, payload.alg);

console.log(`credential  ${payload.credentialId}`);
console.log(`server      ${payload.baseUrl}`);
console.log(`algorithm   ${payload.alg === -7 ? 'ES256' : 'EdDSA'}`);
console.log('');

if (flags.has('--dry-run')) {
  // Build one assertion against a placeholder challenge and show every byte.
  const assertion = await createAssertionResponse({
    keyStore,
    credential: {
      credentialId: decodeBase64Url(payload.credentialId),
      userHandle: decodeBase64Url(payload.userHandle),
      rpId: payload.rpId,
      origin: payload.origin,
    },
    challenge: 'ZHJ5LXJ1bi1jaGFsbGVuZ2U',
  });
  console.log('clientDataJSON');
  console.log(`  ${new TextDecoder().decode(decodeBase64Url(assertion.response.clientDataJSON))}`);
  const authData = decodeBase64Url(assertion.response.authenticatorData);
  console.log('authenticatorData');
  console.log(
    `  ${String(authData.length)} bytes, flags 0x${authData[32].toString(16).padStart(2, '0')}`,
  );
  console.log(`  rpIdHash  ${Buffer.from(authData.subarray(0, 32)).toString('hex')}`);
  console.log(`  signCount ${String(new DataView(authData.buffer).getUint32(33, false))}`);
  console.log('signature (DER)');
  console.log(`  ${Buffer.from(decodeBase64Url(assertion.response.signature)).toString('hex')}`);

  const proof = await createDpopProof({
    keyStore,
    method: 'GET',
    url: new URL('/api/machine/v1/whoami', payload.baseUrl).toString(),
    accessToken: 'placeholder-session-token',
  });
  const [header, claims] = proof.split('.');
  console.log('');
  console.log('DPoP proof');
  console.log(`  header  ${new TextDecoder().decode(decodeBase64Url(header))}`);
  console.log(`  payload ${new TextDecoder().decode(decodeBase64Url(claims))}`);
  process.exit(0);
}

const client = new MachineClient({ payload, keyStore });

try {
  // One ceremony, then a DPoP proof per request.
  const session = await client.authenticate();
  console.log(`session opened, expires ${new Date(session.expiresAt).toISOString()}`);

  const whoami = await client.fetch('/api/machine/v1/whoami');
  console.log('');
  console.log('GET /api/machine/v1/whoami');
  console.log(JSON.stringify(await whoami.json(), null, 2));

  const clients = await client.fetch('/api/machine/v1/clients');
  const body = (await clients.json()) as { clients: { email: string; role: string }[] };
  console.log('');
  console.log(`GET /api/machine/v1/clients -> ${String(body.clients.length)} client(s)`);
  for (const entry of body.clients) {
    console.log(`  ${entry.email}  (${entry.role})`);
  }
} catch (error) {
  if (error instanceof MachineClientError) {
    fail(`${error.code}: ${error.message} (HTTP ${String(error.status)})`);
  }
  throw error;
}
