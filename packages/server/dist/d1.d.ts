import { L as LocalWebAuthnStore, E as EnrollmentGrantRecord, a as EnrollmentSession, C as ChallengeRecord, b as ChallengeKind, c as ConsumedChallenge, d as Credential, e as CompleteRegistrationInput, f as CompleteAuthenticationInput, S as SessionIdentity, g as CleanupResult } from './types-Cel_fkBK.js';
import '@simplewebauthn/server';

type D1ResultLike<Row = Record<string, unknown>> = {
    results: Row[];
    success: boolean;
    meta: {
        changes?: number;
    };
};
type D1PreparedStatementLike = {
    bind(...values: unknown[]): D1PreparedStatementLike;
    first<Row = Record<string, unknown>>(): Promise<Row | null>;
    all<Row = Record<string, unknown>>(): Promise<D1ResultLike<Row>>;
    run<Row = Record<string, unknown>>(): Promise<D1ResultLike<Row>>;
};
type D1DatabaseLike = {
    prepare(sql: string): D1PreparedStatementLike;
    batch(statements: D1PreparedStatementLike[]): Promise<D1ResultLike[]>;
    exec(sql: string): Promise<unknown>;
};
declare function migrateD1(database: D1DatabaseLike, now?: number): Promise<void>;
declare class D1LocalWebAuthnStore implements LocalWebAuthnStore {
    #private;
    constructor(database: D1DatabaseLike);
    replaceEnrollmentGrant(record: EnrollmentGrantRecord): Promise<void>;
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
}

export { type D1DatabaseLike, D1LocalWebAuthnStore, type D1PreparedStatementLike, type D1ResultLike, migrateD1 };
