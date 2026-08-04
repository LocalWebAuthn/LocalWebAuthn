import { L as LocalWebAuthnStore, E as EnrollmentGrantRecord, a as EnrollmentSession, C as ChallengeRecord, b as ChallengeKind, c as ConsumedChallenge, d as Credential, e as CompleteRegistrationInput, f as CompleteAuthenticationInput, S as SessionIdentity, R as RevokedSession, g as RevokeCredentialResult, h as CleanupResult } from './types-sZ3WVqGy.js';
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
/**
 * Create or update the `localwebauthn_*` tables. Idempotent — safe to call on
 * every start.
 *
 * Enables `PRAGMA foreign_keys = ON` on this connection. SQLite does not enforce
 * foreign keys unless that pragma is set; keep using the same connection for
 * the store so the schema constraints remain active.
 */
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
    revokeCredential(userId: string, credentialId: string, now: number, options?: {
        allowLastCredential?: boolean;
    }): Promise<RevokeCredentialResult>;
    revokeUserAuthentication(userId: string, now: number): Promise<void>;
    cleanup(now: number): Promise<CleanupResult>;
}

export { type SqliteDatabase, SqliteLocalWebAuthnStore, type SqliteRunResult, type SqliteStatement, migrateSqlite };
