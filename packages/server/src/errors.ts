export type LocalWebAuthnErrorCode =
  | 'invalid_configuration'
  | 'invalid_enrollment'
  | 'enrollment_not_authorized'
  | 'invalid_ceremony'
  | 'registration_failed'
  | 'authentication_failed'
  | 'unauthenticated'
  | 'credential_not_found'
  | 'last_credential';

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
