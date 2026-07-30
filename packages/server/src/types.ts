import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  Base64URLString,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  WebAuthnCredential,
} from '@simplewebauthn/server';

export type AuthUser = {
  id: string;
  webAuthnUserHandle: Uint8Array;
  name: string;
  displayName: string;
  active: boolean;
};

export type UserProvider = {
  getUser(userId: string): Promise<AuthUser | null>;
};

export type Credential = {
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

export type SessionIdentity = {
  userId: string;
  credentialId: string;
  authenticatedAt: number;
  expiresAt: number;
  lastSeenAt: number;
};

export type EnrollmentGrantRecord = {
  id: string;
  userId: string;
  tokenHash: Uint8Array;
  expiresAt: number;
  approvedByUserId: string | null;
  createdAt: number;
};

export type EnrollmentSession = {
  grantId: string;
  userId: string;
  sessionHash: Uint8Array;
  sessionExpiresAt: number;
};

export type ChallengeKind = 'registration' | 'authentication';

export type ChallengeRecord = {
  idHash: Uint8Array;
  kind: ChallengeKind;
  challenge: string;
  userId: string | null;
  grantId: string | null;
  authorizationSessionHash: Uint8Array | null;
  expiresAt: number;
  createdAt: number;
};

export type ConsumedChallenge = Omit<ChallengeRecord, 'idHash' | 'expiresAt' | 'createdAt'>;

export type NewCredential = Omit<Credential, 'lastUsedAt' | 'revokedAt'>;

export type NewSession = {
  idHash: Uint8Array;
  userId: string;
  credentialId: string;
  authenticatedAt: number;
  expiresAt: number;
  lastSeenAt: number;
};

export type CompleteRegistrationInput = {
  challenge: ConsumedChallenge;
  enrollmentSessionHash: Uint8Array | null;
  authenticatedSessionHash: Uint8Array | null;
  credential: NewCredential;
  session: NewSession;
  now: number;
};

export type CompleteAuthenticationInput = {
  credentialId: string;
  previousCounter: number;
  newCounter: number;
  session: NewSession;
  now: number;
};

export type CleanupResult = {
  enrollmentGrants: number;
  challenges: number;
  sessions: number;
  orphanedCredentials: number;
};

export type LocalWebAuthnStore = {
  replaceEnrollmentGrant(record: EnrollmentGrantRecord): Promise<string[]>;
  exchangeEnrollment(
    tokenHash: Uint8Array,
    sessionHash: Uint8Array,
    sessionExpiresAt: number,
    now: number,
  ): Promise<EnrollmentSession | null>;
  resolveEnrollmentSession(sessionHash: Uint8Array, now: number): Promise<EnrollmentSession | null>;
  createChallenge(record: ChallengeRecord): Promise<void>;
  consumeChallenge(
    idHash: Uint8Array,
    kind: ChallengeKind,
    now: number,
  ): Promise<ConsumedChallenge | null>;
  listCredentials(userId: string, includeRevoked?: boolean): Promise<Credential[]>;
  getCredential(credentialId: string): Promise<Credential | null>;
  completeRegistration(input: CompleteRegistrationInput): Promise<boolean>;
  completeAuthentication(input: CompleteAuthenticationInput): Promise<boolean>;
  resolveSession(
    idHash: Uint8Array,
    now: number,
    idleExpiresBefore: number,
  ): Promise<SessionIdentity | null>;
  touchSession(idHash: Uint8Array, now: number): Promise<boolean>;
  revokeSession(idHash: Uint8Array, now: number): Promise<boolean>;
  revokeCredential(userId: string, credentialId: string, now: number): Promise<boolean>;
  revokeUserAuthentication(userId: string, now: number): Promise<void>;
  cleanup(now: number): Promise<CleanupResult>;
};

export type LocalWebAuthnEvent =
  | {
      type:
        | 'enrollment.issued'
        | 'enrollment.exchanged'
        | 'enrollment.completed'
        | 'enrollment.revoked';
      at: number;
      userId: string;
      grantId: string;
    }
  | {
      type: 'credential.registered' | 'credential.authenticated' | 'credential.revoked';
      at: number;
      userId: string;
      credentialId: string;
    }
  | {
      type: 'session.created' | 'session.revoked';
      at: number;
      userId?: string;
      credentialId?: string;
    };

export type LocalWebAuthnDurations = {
  enrollmentGrantMs?: number;
  enrollmentSessionMs?: number;
  challengeMs?: number;
  sessionIdleMs?: number;
  sessionAbsoluteMs?: number;
};

export type CeremonyProvider = {
  generateRegistrationOptions(
    options: Parameters<typeof import('@simplewebauthn/server').generateRegistrationOptions>[0],
  ): Promise<PublicKeyCredentialCreationOptionsJSON>;
  verifyRegistrationResponse(
    options: Parameters<typeof import('@simplewebauthn/server').verifyRegistrationResponse>[0],
  ): ReturnType<typeof import('@simplewebauthn/server').verifyRegistrationResponse>;
  generateAuthenticationOptions(
    options: Parameters<typeof import('@simplewebauthn/server').generateAuthenticationOptions>[0],
  ): Promise<PublicKeyCredentialRequestOptionsJSON>;
  verifyAuthenticationResponse(
    options: Parameters<typeof import('@simplewebauthn/server').verifyAuthenticationResponse>[0],
  ): ReturnType<typeof import('@simplewebauthn/server').verifyAuthenticationResponse>;
};

export type LocalWebAuthnOptions = {
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

export type EnrollmentIssue = {
  grantId: string;
  enrollmentToken: string;
  enrollmentUrl: string;
  expiresAt: number;
};

export type EnrollmentExchange = {
  enrollmentSessionToken: string;
  expiresAt: number;
  user: Pick<AuthUser, 'id' | 'name' | 'displayName'>;
};

export type RegistrationOptionsResult = {
  options: PublicKeyCredentialCreationOptionsJSON;
  challengeToken: string;
  expiresAt: number;
};

export type RegistrationVerificationResult = {
  verified: true;
  sessionToken: string;
  expiresAt: number;
  credentialId: string;
};

export type AuthenticationOptionsResult = {
  options: PublicKeyCredentialRequestOptionsJSON;
  challengeToken: string;
  expiresAt: number;
};

export type AuthenticationVerificationResult = {
  verified: true;
  sessionToken: string;
  expiresAt: number;
  credentialId: string;
  user: Pick<AuthUser, 'id' | 'name' | 'displayName'>;
};

export type RegistrationVerificationInput = {
  response: RegistrationResponseJSON;
  challengeToken: string;
  enrollmentSessionToken?: string;
  sessionToken?: string;
  label?: string;
};

export type AuthenticationVerificationInput = {
  response: AuthenticationResponseJSON;
  challengeToken: string;
};

export function toWebAuthnCredential(credential: Credential): WebAuthnCredential {
  return {
    id: credential.id,
    publicKey: Uint8Array.from(credential.publicKey),
    counter: credential.counter,
    transports: credential.transports,
  };
}

export type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
};
