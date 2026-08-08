export type LocalWebAuthnErrorCode =
  | 'invalid_configuration'
  | 'invalid_enrollment'
  | 'enrollment_not_authorized'
  | 'invalid_ceremony'
  | 'registration_failed'
  | 'authentication_failed'
  | 'unauthenticated'
  | 'credential_not_found'
  | 'last_credential'
  /**
   * The authorizing session's credential kind is configured `canRegister: false`
   * — a machine credential may authenticate but may not enroll another
   * credential. See {@link CredentialKindPolicy.canRegister}.
   */
  | 'registration_not_permitted'
  /** A DPoP proof was absent, malformed, replayed, or signed by the wrong key. */
  | 'invalid_dpop_proof';

export class LocalWebAuthnError extends Error {
  readonly code: LocalWebAuthnErrorCode;
  readonly status: number;

  constructor(code: LocalWebAuthnErrorCode, message: string, status: number) {
    super(message);
    this.name = 'LocalWebAuthnError';
    this.code = code;
    this.status = status;
  }
}

export function isLocalWebAuthnError(value: unknown): value is LocalWebAuthnError {
  return value instanceof LocalWebAuthnError;
}
