/**
 * A WebAuthn authenticator implemented in software.
 *
 * "Authenticator" in WebAuthn is a *role*, not a device class. Its obligations
 * are to hold a key pair, emit `authenticatorData`, and sign — all three of which
 * are discharged below in a few dozen lines. The W3C specification standardises a
 * Virtual Authenticator precisely so software can occupy the role, and every
 * WebAuthn test suite in existence drives one.
 *
 * What such an authenticator cannot honestly claim is human presence. It sets the
 * UP and UV bits because a conforming relying party checks them, but those bits
 * are a program's statement about itself, and a server must never read them as
 * evidence of a person. That is what the credential's server-side `kind` is for.
 */

import { concat, encodeBase64Url, randomBytes, sha256, utf8 } from './bytes.js';
import { type CborValue, encodeCborMap } from './cbor.js';
import type { MachineKeyStore } from './keystore.js';

/** `authenticatorData` flag bits (WebAuthn Level 3, section 6.1). */
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;

/**
 * All-zero AAGUID.
 *
 * A self-chosen AAGUID would be a claim this authenticator makes about its own
 * make and model, which a relying party has no way to check and must not rely
 * on. Zero is the honest value and what `fmt: "none"` implies anyway.
 */
const AAGUID = new Uint8Array(16);

export type SoftwareCredential = {
  /** Raw credential ID; the server stores its base64url form as the primary key. */
  credentialId: Uint8Array;
  /** 32-byte WebAuthn user handle, from `options.user.id`. */
  userHandle: Uint8Array;
  rpId: string;
  /** Exact string written into `clientDataJSON.origin`. */
  origin: string;
};

/** Minimal shape of the registration response this authenticator emits. */
export type SoftwareRegistrationResponse = {
  id: string;
  rawId: string;
  type: 'public-key';
  clientExtensionResults: Record<string, never>;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports: string[];
  };
};

/** Minimal shape of the assertion this authenticator emits. */
export type SoftwareAssertionResponse = {
  id: string;
  rawId: string;
  type: 'public-key';
  clientExtensionResults: Record<string, never>;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle: string;
  };
};

function clientDataJSON(
  type: 'webauthn.create' | 'webauthn.get',
  challenge: string,
  origin: string,
) {
  // The challenge is echoed byte-for-byte: it arrives base64url and re-encoding
  // it will not reliably round-trip.
  return utf8(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
}

/**
 * Build `authenticatorData`.
 *
 * `signCount` is fixed at zero, which WebAuthn permits and this project's server
 * accepts as a `0 → 0` advance. Three reasons, in order of weight: replay is
 * already defeated by the server's single-use challenge, which is a stronger and
 * server-owned control; clone detection is meaningless for a key in a file;
 * and a real counter makes concurrent sessions from one credential fight over a
 * single compare-and-swap, which is exactly the usage this package is for.
 */
async function authenticatorData(
  rpId: string,
  flags: number,
  attestedCredentialData?: Uint8Array,
): Promise<Uint8Array> {
  const header = new Uint8Array(37);
  header.set(await sha256(rpId), 0);
  header[32] = flags;
  // Bytes 33..37 are the big-endian signCount, left at zero.
  return attestedCredentialData ? concat(header, attestedCredentialData) : header;
}

/**
 * Produce a registration response for a freshly generated key.
 *
 * `BE` and `BS` are deliberately clear, so the server records
 * `deviceType: 'singleDevice'` and `backedUp: false` — honest for a key that
 * lives in a file, and notably *not* the "synced passkey" a `multiDevice` row
 * would imply.
 *
 * With `fmt: "none"` there is no attestation signature at all: the public key is
 * simply asserted, and the first assertion is what proves the private half
 * exists.
 */
export async function createRegistrationResponse(input: {
  keyStore: MachineKeyStore;
  challenge: string;
  rpId: string;
  origin: string;
  credentialId?: Uint8Array;
}): Promise<{ response: SoftwareRegistrationResponse; credentialId: Uint8Array }> {
  const credentialId = input.credentialId ?? randomBytes(32);
  const publicKeyCose = await input.keyStore.publicKeyCose();

  const credentialIdLength = new Uint8Array(2);
  new DataView(credentialIdLength.buffer).setUint16(0, credentialId.length, false);
  const attestedCredentialData = concat(AAGUID, credentialIdLength, credentialId, publicKeyCose);

  const authData = await authenticatorData(
    input.rpId,
    FLAG_UP | FLAG_UV | FLAG_AT,
    attestedCredentialData,
  );
  const attestationObject = encodeCborMap(
    new Map<string, CborValue>([
      ['fmt', 'none'],
      ['attStmt', new Map()],
      ['authData', authData],
    ]),
  );

  return {
    credentialId,
    response: {
      id: encodeBase64Url(credentialId),
      rawId: encodeBase64Url(credentialId),
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: encodeBase64Url(
          clientDataJSON('webauthn.create', input.challenge, input.origin),
        ),
        attestationObject: encodeBase64Url(attestationObject),
        transports: [],
      },
    },
  };
}

/** Produce an assertion for a server-issued challenge. */
export async function createAssertionResponse(input: {
  keyStore: MachineKeyStore;
  credential: SoftwareCredential;
  challenge: string;
}): Promise<SoftwareAssertionResponse> {
  const clientData = clientDataJSON('webauthn.get', input.challenge, input.credential.origin);
  const authData = await authenticatorData(input.credential.rpId, FLAG_UP | FLAG_UV);
  const signature = await input.keyStore.signWebAuthn(concat(authData, await sha256(clientData)));

  return {
    id: encodeBase64Url(input.credential.credentialId),
    rawId: encodeBase64Url(input.credential.credentialId),
    type: 'public-key',
    clientExtensionResults: {},
    response: {
      clientDataJSON: encodeBase64Url(clientData),
      authenticatorData: encodeBase64Url(authData),
      signature: encodeBase64Url(signature),
      // Required: this project's server compares it against the stored user
      // handle, so a discoverable-credential assertion without it is refused.
      userHandle: encodeBase64Url(input.credential.userHandle),
    },
  };
}
