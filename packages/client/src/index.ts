/**
 * A WebAuthn authenticator in software, for programs with no browser and no human.
 *
 * This entry point works entirely through {@link MachineKeyStore}: it asks a signer
 * for a public key and for signatures, and never handles private key bytes. That is
 * what lets the same code run over a file-based key, an SSH-style agent, a TPM, a
 * Secure Enclave or a cloud KMS.
 *
 * Generating or reading a raw private key — and the credential-file format that
 * carries one — lives in `@localwebauthn/client/file-key`, deliberately behind its
 * own import so the choice is visible at the call site.
 */

export {
  createAssertionResponse,
  createRegistrationResponse,
  type SoftwareAssertionResponse,
  type SoftwareCredential,
  type SoftwareRegistrationResponse,
} from './authenticator.js';
export {
  concat,
  decodeBase64,
  decodeBase64Url,
  encodeBase64,
  encodeBase64Url,
  randomBytes,
  sha256,
  utf8,
} from './bytes.js';
export {
  CREDENTIAL_PAYLOAD_VERSION,
  type CredentialPayload,
  parseCredentialPayload,
} from './credential-file.js';
export { createDpopProof } from './dpop.js';
export { rawSignatureToDer } from './ecdsa.js';
export { type CoseAlgorithm, EDDSA, ES256, type MachineKeyStore } from './keystore.js';
export { MachineClient, MachineClientError, type MachineClientOptions } from './machine-client.js';
