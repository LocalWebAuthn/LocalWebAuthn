import type { EnrollmentGrantState } from './types.js';

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
  | 'invalid_dpop_proof'
  /**
   * A DPoP proof carried no nonce, or one the server no longer recognises. The
   * host should answer `401` with `WWW-Authenticate: DPoP
   * error="use_dpop_nonce"` and a fresh `DPoP-Nonce` header, which the client
   * echoes on its retry.
   */
  | 'dpop_nonce_required'
  /**
   * A revocation could not be shown to have finished: credentials kept appearing
   * as fast as they were revoked, so the operation stopped at its pass bound
   * without reaching a quiet state. Some credentials *were* revoked. Treat this
   * as remediation **not** complete — suspend the user's ability to register
   * (or deactivate the user via `getUser`) and retry.
   */
  | 'revocation_not_converged';

export class LocalWebAuthnError extends Error {
  readonly code: LocalWebAuthnErrorCode;
  readonly status: number;
  /**
   * Why an enrollment token was refused, on an `invalid_enrollment` thrown by
   * `exchangeEnrollment`. Absent everywhere else, and absent when the store does
   * not implement `enrollmentGrantState`.
   *
   * The `code` stays `invalid_enrollment` whatever this says, so a host that
   * ignores it behaves exactly as before. Read it to choose the message: only
   * `'used'` is worth telling somebody about, because an enrollment link is
   * single-use and they may not be the one who used it.
   */
  declare readonly enrollmentState?: EnrollmentGrantState;

  constructor(
    code: LocalWebAuthnErrorCode,
    message: string,
    status: number,
    details: { enrollmentState?: EnrollmentGrantState } = {},
  ) {
    super(message);
    this.name = 'LocalWebAuthnError';
    this.code = code;
    this.status = status;
    if (details.enrollmentState) {
      this.enrollmentState = details.enrollmentState;
    }
  }
}

export function isLocalWebAuthnError(value: unknown): value is LocalWebAuthnError {
  return value instanceof LocalWebAuthnError;
}
