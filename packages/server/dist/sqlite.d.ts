import { L as LocalWebAuthnStore, E as EnrollmentGrantRecord, a as EnrollmentSession, C as ChallengeRecord, b as ChallengeKind, c as ConsumedChallenge, d as Credential, e as CompleteRegistrationInput, f as CompleteAuthenticationInput, S as SessionIdentity, g as CleanupResult } from './types-CtkYtX14.js';
import '@simplewebauthn/server';

type SqliteRunResult = {
    changes: number;
};
type SqliteStatement = {
    run(...parameters: unknown[]): SqliteRunResult;
    get(...parameters: unknown[]): unknown;
    all(...parameters: unknown[]): unknown[];
};
type SqliteDatabase = {
    exec(sql: string): unknown;
    prepare(sql: string): SqliteStatement;
    transaction<T>(operation: () => T): () => T;
};
declare function migrateSqlite(database: SqliteDatabase, now?: number): void;
declare class SqliteLocalWebAuthnStore implements LocalWebAuthnStore {
    #private;
    constructor(database: SqliteDatabase);
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
}

export { type SqliteDatabase, SqliteLocalWebAuthnStore, type SqliteRunResult, type SqliteStatement, migrateSqlite };
