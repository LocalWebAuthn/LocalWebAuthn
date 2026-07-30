import * as _simplewebauthn_server from '@simplewebauthn/server';
import { Base64URLString, AuthenticatorTransportFuture, PublicKeyCredentialRequestOptionsJSON, AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON, RegistrationResponseJSON } from '@simplewebauthn/server';

type AuthUser = {
    id: string;
    webAuthnUserHandle: Uint8Array;
    name: string;
    displayName: string;
    active: boolean;
};
type UserProvider = {
    getUser(userId: string): Promise<AuthUser | null>;
};
type Credential = {
    id: Base64URLString;
    userId: string;
    publicKey: Uint8Array;
    counter: number;
    transports: AuthenticatorTransportFuture[];
    deviceType: 'singleDevice' | 'multiDevice';
    backedUp: boolean;
    label: string;
    createdAt: number;
    lastUsedAt: number | null;
    revokedAt: number | null;
};
type SessionIdentity = {
    userId: string;
    credentialId: string;
    authenticatedAt: number;
    expiresAt: number;
    lastSeenAt: number;
};
type EnrollmentGrantRecord = {
    id: string;
    userId: string;
    tokenHash: Uint8Array;
    expiresAt: number;
    approvedByUserId: string | null;
    createdAt: number;
};
type EnrollmentSession = {
    grantId: string;
    userId: string;
    sessionHash: Uint8Array;
    sessionExpiresAt: number;
};
type ChallengeKind = 'registration' | 'authentication';
type ChallengeRecord = {
    idHash: Uint8Array;
    kind: ChallengeKind;
    challenge: string;
    userId: string | null;
    grantId: string | null;
    authorizationSessionHash: Uint8Array | null;
    expiresAt: number;
    createdAt: number;
};
type ConsumedChallenge = Omit<ChallengeRecord, 'idHash' | 'expiresAt' | 'createdAt'>;
type NewCredential = Omit<Credential, 'lastUsedAt' | 'revokedAt'>;
type NewSession = {
    idHash: Uint8Array;
    userId: string;
    credentialId: string;
    authenticatedAt: number;
    expiresAt: number;
    lastSeenAt: number;
};
type CompleteRegistrationInput = {
    challenge: ConsumedChallenge;
    enrollmentSessionHash: Uint8Array | null;
    authenticatedSessionHash: Uint8Array | null;
    credential: NewCredential;
    session: NewSession;
    now: number;
};
type CompleteAuthenticationInput = {
    credentialId: string;
    previousCounter: number;
    newCounter: number;
    session: NewSession;
    now: number;
};
type CleanupResult = {
    enrollmentGrants: number;
    challenges: number;
    sessions: number;
    orphanedCredentials: number;
};
type LocalWebAuthnStore = {
    replaceEnrollmentGrant(record: EnrollmentGrantRecord): Promise<string[]>;
    exchangeEnrollment(tokenHash: Uint8Array, sessionHash: Uint8Array, sessionExpiresAt: number, now: number): Promise<EnrollmentSession | null>;
    resolveEnrollmentSession(sessionHash: Uint8Array, now: number): Promise<EnrollmentSession | null>;
    createChallenge(record: ChallengeRecord): Promise<void>;
    consumeChallenge(idHash: Uint8Array, kind: ChallengeKind, now: number): Promise<ConsumedChallenge | null>;
    listCredentials(userId: string, includeRevoked?: boolean): Promise<Credential[]>;
    getCredential(credentialId: string): Promise<Credential | null>;
    completeRegistration(input: CompleteRegistrationInput): Promise<boolean>;
    completeAuthentication(input: CompleteAuthenticationInput): Promise<boolean>;
    resolveSession(idHash: Uint8Array, now: number, idleExpiresBefore: number): Promise<SessionIdentity | null>;
    touchSession(idHash: Uint8Array, now: number): Promise<boolean>;
    revokeSession(idHash: Uint8Array, now: number): Promise<boolean>;
    revokeCredential(userId: string, credentialId: string, now: number): Promise<boolean>;
    revokeUserAuthentication(userId: string, now: number): Promise<void>;
    cleanup(now: number): Promise<CleanupResult>;
};
type LocalWebAuthnEvent = {
    type: 'enrollment.issued' | 'enrollment.exchanged' | 'enrollment.completed' | 'enrollment.revoked';
    at: number;
    userId: string;
    grantId: string;
} | {
    type: 'credential.registered' | 'credential.authenticated' | 'credential.revoked';
    at: number;
    userId: string;
    credentialId: string;
} | {
    type: 'session.created' | 'session.revoked';
    at: number;
    userId?: string;
    credentialId?: string;
};
type LocalWebAuthnDurations = {
    enrollmentGrantMs?: number;
    enrollmentSessionMs?: number;
    challengeMs?: number;
    sessionIdleMs?: number;
    sessionAbsoluteMs?: number;
};
type CeremonyProvider = {
    generateRegistrationOptions(options: Parameters<typeof _simplewebauthn_server.generateRegistrationOptions>[0]): Promise<PublicKeyCredentialCreationOptionsJSON>;
    verifyRegistrationResponse(options: Parameters<typeof _simplewebauthn_server.verifyRegistrationResponse>[0]): ReturnType<typeof _simplewebauthn_server.verifyRegistrationResponse>;
    generateAuthenticationOptions(options: Parameters<typeof _simplewebauthn_server.generateAuthenticationOptions>[0]): Promise<PublicKeyCredentialRequestOptionsJSON>;
    verifyAuthenticationResponse(options: Parameters<typeof _simplewebauthn_server.verifyAuthenticationResponse>[0]): ReturnType<typeof _simplewebauthn_server.verifyAuthenticationResponse>;
};
type LocalWebAuthnOptions = {
    rpName: string;
    rpId: string;
    expectedOrigins: string | string[];
    publicOrigin?: string;
    enrollmentPath?: string;
    store: LocalWebAuthnStore;
    users: UserProvider;
    durations?: LocalWebAuthnDurations;
    now?: () => number;
    randomBytes?: (length: number) => Uint8Array;
    ceremonies?: CeremonyProvider;
    onEvent?: (event: LocalWebAuthnEvent) => void | Promise<void>;
};
type EnrollmentIssue = {
    grantId: string;
    enrollmentToken: string;
    enrollmentUrl: string;
    expiresAt: number;
};
type EnrollmentExchange = {
    enrollmentSessionToken: string;
    expiresAt: number;
    user: Pick<AuthUser, 'id' | 'name' | 'displayName'>;
};
type RegistrationOptionsResult = {
    options: PublicKeyCredentialCreationOptionsJSON;
    challengeToken: string;
    expiresAt: number;
};
type RegistrationVerificationResult = {
    verified: true;
    sessionToken: string;
    expiresAt: number;
    credentialId: string;
};
type AuthenticationOptionsResult = {
    options: PublicKeyCredentialRequestOptionsJSON;
    challengeToken: string;
    expiresAt: number;
};
type AuthenticationVerificationResult = {
    verified: true;
    sessionToken: string;
    expiresAt: number;
    credentialId: string;
    user: Pick<AuthUser, 'id' | 'name' | 'displayName'>;
};
type RegistrationVerificationInput = {
    response: RegistrationResponseJSON;
    challengeToken: string;
    enrollmentSessionToken?: string;
    sessionToken?: string;
    label?: string;
};
type AuthenticationVerificationInput = {
    response: AuthenticationResponseJSON;
    challengeToken: string;
};

export type { AuthenticationOptionsResult as A, ChallengeRecord as C, EnrollmentGrantRecord as E, LocalWebAuthnStore as L, NewCredential as N, RegistrationOptionsResult as R, SessionIdentity as S, UserProvider as U, EnrollmentSession as a, ChallengeKind as b, ConsumedChallenge as c, Credential as d, CompleteRegistrationInput as e, CompleteAuthenticationInput as f, CleanupResult as g, LocalWebAuthnOptions as h, EnrollmentIssue as i, EnrollmentExchange as j, RegistrationVerificationInput as k, RegistrationVerificationResult as l, AuthenticationVerificationInput as m, AuthenticationVerificationResult as n, AuthUser as o, CeremonyProvider as p, LocalWebAuthnDurations as q, LocalWebAuthnEvent as r, NewSession as s };
