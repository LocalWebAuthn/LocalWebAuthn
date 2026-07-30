import { h as LocalWebAuthnOptions, i as EnrollmentIssue, j as EnrollmentExchange, R as RegistrationOptionsResult, k as RegistrationVerificationInput, l as RegistrationVerificationResult, A as AuthenticationOptionsResult, m as AuthenticationVerificationInput, n as AuthenticationVerificationResult, o as AuthUser, S as SessionIdentity, d as Credential, g as CleanupResult } from './types-Cel_fkBK.js';
export { p as CeremonyProvider, b as ChallengeKind, C as ChallengeRecord, f as CompleteAuthenticationInput, e as CompleteRegistrationInput, c as ConsumedChallenge, E as EnrollmentGrantRecord, a as EnrollmentSession, q as LocalWebAuthnDurations, r as LocalWebAuthnEvent, L as LocalWebAuthnStore, N as NewCredential, s as NewSession, U as UserProvider } from './types-Cel_fkBK.js';
export { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';

declare function defaultRandomBytes(length: number): Uint8Array;
declare function sha256(value: string | Uint8Array): Promise<Uint8Array>;
declare function encodeBase32(bytes: Uint8Array): string;
declare function encodeBase64Url(bytes: Uint8Array): string;
declare function decodeBase64Url(value: string): Uint8Array | null;
declare function equalBytes(left: Uint8Array, right: Uint8Array): boolean;
declare function createUserHandle(randomBytes?: typeof defaultRandomBytes): Uint8Array;
declare function createEnrollmentToken(randomBytes?: typeof defaultRandomBytes): string;
declare function createOpaqueToken(randomBytes?: typeof defaultRandomBytes): string;

type LocalWebAuthnErrorCode = 'invalid_configuration' | 'invalid_enrollment' | 'enrollment_not_authorized' | 'invalid_ceremony' | 'registration_failed' | 'authentication_failed' | 'unauthenticated' | 'credential_not_found' | 'last_credential';
declare class LocalWebAuthnError extends Error {
    readonly code: LocalWebAuthnErrorCode;
    readonly status: number;
    constructor(code: LocalWebAuthnErrorCode, message: string, status: number);
}
declare function isLocalWebAuthnError(value: unknown): value is LocalWebAuthnError;

type NormalizedConfig = {
    rpName: string;
    rpId: string;
    expectedOrigins: string[];
    publicOrigin: string;
    enrollmentPath: string;
    durations: {
        enrollmentGrantMs: number;
        enrollmentSessionMs: number;
        challengeMs: number;
        sessionIdleMs: number;
        sessionAbsoluteMs: number;
    };
};

declare class LocalWebAuthn {
    #private;
    readonly config: NormalizedConfig;
    constructor(options: LocalWebAuthnOptions);
    issueEnrollment(userId: string, approvedByUserId?: string): Promise<EnrollmentIssue>;
    exchangeEnrollment(enrollmentToken: string): Promise<EnrollmentExchange>;
    registrationOptions(input: {
        enrollmentSessionToken?: string;
        sessionToken?: string;
    }): Promise<RegistrationOptionsResult>;
    verifyRegistration(input: RegistrationVerificationInput): Promise<RegistrationVerificationResult>;
    authenticationOptions(): Promise<AuthenticationOptionsResult>;
    verifyAuthentication(input: AuthenticationVerificationInput): Promise<AuthenticationVerificationResult>;
    resolveSession(sessionToken: string, touch?: boolean): Promise<{
        user: AuthUser;
        session: SessionIdentity;
    } | null>;
    revokeSession(sessionToken: string): Promise<boolean>;
    listCredentials(userId: string, includeRevoked?: boolean): Promise<Credential[]>;
    revokeCredential(userId: string, credentialId: string, options?: {
        allowLastCredential?: boolean;
    }): Promise<boolean>;
    revokeUserAuthentication(userId: string): Promise<void>;
    cleanup(): Promise<CleanupResult>;
}

export { AuthUser, AuthenticationOptionsResult, AuthenticationVerificationInput, AuthenticationVerificationResult, CleanupResult, Credential, EnrollmentExchange, EnrollmentIssue, LocalWebAuthn, LocalWebAuthnError, type LocalWebAuthnErrorCode, LocalWebAuthnOptions, RegistrationOptionsResult, RegistrationVerificationInput, RegistrationVerificationResult, SessionIdentity, createEnrollmentToken, createOpaqueToken, createUserHandle, decodeBase64Url, encodeBase32, encodeBase64Url, equalBytes, isLocalWebAuthnError, sha256 };
