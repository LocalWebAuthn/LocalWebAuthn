import { L as LocalWebAuthnStore, E as EnrollmentGrantRecord, a as EnrollmentSession, C as ChallengeRecord, b as ChallengeKind, c as ConsumedChallenge, d as Credential, e as CompleteRegistrationInput, f as CompleteAuthenticationInput, S as SessionIdentity, R as RevokedSession, g as RevokeCredentialResult, h as CleanupResult } from './types-DdbmOKqa.js';
import '@simplewebauthn/server';

type SqliteRunResult = {
    changes: number;
};
type SqliteStatement = {
    run(...parameters: unknown[]): SqliteRunResult;
    get(...parameters: unknown[]): unknown;
    all(...parameters: unknown[]): unknown[];
};
/**
 * better-sqlite3's transaction function: callable (BEGIN DEFERRED) with an
 * `immediate()` variant (BEGIN IMMEDIATE). The adapter always uses
 * `immediate()`: a deferred transaction that reads before writing cannot be
 * retried by `busy_timeout` under WAL once another connection has written
 * (`SQLITE_BUSY_SNAPSHOT`), and every transaction here writes.
 */
type SqliteTransaction<T> = {
    (): T;
    immediate(): T;
};
type SqliteDatabase = {
    exec(sql: string): unknown;
    prepare(sql: string): SqliteStatement;
    transaction<T>(operation: () => T): SqliteTransaction<T>;
};
declare function migrateSqlite(database: SqliteDatabase, now?: number): void;
/**
 * {@link LocalWebAuthnStore} backed by better-sqlite3 (or any driver with the
 * same synchronous `prepare`/`transaction` shape).
 *
 * Every multi-statement operation runs inside a real SQLite transaction, so
 * partial writes cannot be observed or left behind. The constructor enables
 * foreign-key enforcement on the given connection.
 */
declare class SqliteLocalWebAuthnStore implements LocalWebAuthnStore {
    #private;
    constructor(database: SqliteDatabase);
    replaceEnrollmentGrant(record: EnrollmentGrantRecord): Promise<string[]>;
    revokePendingEnrollmentGrants(userId: string, now: number, credentialKind: string | null): Promise<string[]>;
    exchangeEnrollment(tokenHash: Uint8Array, sessionHash: Uint8Array, sessionExpiresAt: number, now: number): Promise<EnrollmentSession | null>;
    resolveEnrollmentSession(sessionHash: Uint8Array, now: number): Promise<EnrollmentSession | null>;
    createChallenge(record: ChallengeRecord): Promise<boolean>;
    consumeChallenge(idHash: Uint8Array, kind: ChallengeKind, now: number): Promise<ConsumedChallenge | null>;
    listCredentials(userId: string, includeRevoked?: boolean): Promise<Credential[]>;
    getCredential(credentialId: string): Promise<Credential | null>;
    completeRegistration(input: CompleteRegistrationInput): Promise<boolean>;
    completeAuthentication(input: CompleteAuthenticationInput): Promise<boolean>;
    resolveSession(idHash: Uint8Array, now: number, idleExpiresBefore: number): Promise<SessionIdentity | null>;
    touchSession(idHash: Uint8Array, now: number): Promise<boolean>;
    revokeSession(idHash: Uint8Array, now: number): Promise<RevokedSession | null>;
    revokeUserSessions(userId: string, now: number, idleExpiresBefore: number, exceptSessionHash?: Uint8Array): Promise<number>;
    revokeLiveCredentialSessions(credentialId: string, now: number, idleExpiresBefore: number, exceptSessionHash?: Uint8Array): Promise<number>;
    revokeCredential(userId: string, credentialId: string, now: number, options?: {
        allowLastCredential?: boolean;
    }): Promise<RevokeCredentialResult>;
    revokeUserAuthentication(userId: string, now: number): Promise<void>;
    claimDpopProof(jtiHash: Uint8Array, expiresAt: number): Promise<boolean>;
    claimDpopNonce(slot: number, candidate: string, expiresAt: number): Promise<string>;
    dpopNonces(currentSlot: number, previousSlot: number): Promise<string[]>;
    cleanup(now: number): Promise<CleanupResult>;
}

export { type SqliteDatabase, SqliteLocalWebAuthnStore, type SqliteRunResult, type SqliteStatement, type SqliteTransaction, migrateSqlite };
