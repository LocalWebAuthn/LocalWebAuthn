/**
 * Raw private-key operations: generation, import, and the credential file format.
 *
 * **This is the one part of the client that handles exportable private key
 * material.** It is a separate entry point so that the import line says so — a
 * reviewer scanning `from '@localwebauthn/client/file-key'` knows a key is being
 * generated, read or written, and the default entry point cannot reach any of it.
 *
 * Nothing here is exotic or discouraged: a file-based credential is how a CLI holds
 * a key, and this is the same shape as any API key a service hands out from a web
 * page. It is separated because it deserves a decision, not because it is wrong.
 *
 * Two things to know if you use it:
 *
 * - **A key that reaches a file has copies you cannot see.** Clipboard history, a
 *   Downloads folder, and backups of either. WebCrypto makes no promise that key
 *   material is erased when a reference is dropped, so nothing here claims to shred
 *   or zeroize anything. Treat "the key exists in exactly one place" as a goal, not
 *   a fact.
 * - **Rotation is the answer, not perfect custody.** Minting a replacement and
 *   revoking the old credential takes seconds and needs no downtime, so a credential
 *   you are unsure about should simply be replaced. See "Rotating an API credential"
 *   in README-DETAIL.org.
 *
 * If your deployment can avoid exportable keys entirely, do: implement
 * {@link MachineKeyStore} over a platform keystore, an agent, a TPM or a KMS, where
 * the process sends bytes to sign and receives a signature but never holds the key.
 * That signer satisfies the default entry point, and you never import this module.
 */

export {
  CREDENTIAL_KEY_VARIABLE,
  CREDENTIAL_VARIABLE,
  formatCredentialFile,
  isKeystoreReference,
  parseCredentialFile,
} from './credential-file.js';
export { generateKeyStore, importKeyStore } from './keystore.js';
