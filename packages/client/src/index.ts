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
  CREDENTIAL_KEY_VARIABLE,
  CREDENTIAL_PAYLOAD_VERSION,
  CREDENTIAL_VARIABLE,
  type CredentialPayload,
  formatCredentialFile,
  isKeystoreReference,
  parseCredentialFile,
  parseCredentialPayload,
} from './credential-file.js';
export { createDpopProof } from './dpop.js';
export { rawSignatureToDer } from './ecdsa.js';
export {
  type CoseAlgorithm,
  EDDSA,
  ES256,
  generateKeyStore,
  importKeyStore,
  type MachineKeyStore,
} from './keystore.js';
export { MachineClient, MachineClientError, type MachineClientOptions } from './machine-client.js';
