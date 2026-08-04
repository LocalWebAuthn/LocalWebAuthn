import { L as LocalWebAuthnStore, E as EnrollmentGrantRecord, a as EnrollmentSession, C as ChallengeRecord, b as ChallengeKind, c as ConsumedChallenge, d as Credential, e as CompleteRegistrationInput, f as CompleteAuthenticationInput, S as SessionIdentity, R as RevokedSession, g as RevokeCredentialResult, h as CleanupResult } from './types-sZ3WVqGy.js';
import '@simplewebauthn/server';

type PostgresQueryResult<Row> = {
    rows: Row[];
    rowCount: number | null;
};
/** The subset of a node-postgres client this adapter uses. */
type PostgresQueryable = {
    query<Row = Record<string, unknown>>(sql: string, parameters?: unknown[]): Promise<PostgresQueryResult<Row>>;
};
type PostgresPoolClient = PostgresQueryable & {
    release(): void;
};
/**
 * A `pg.Pool`, or anything with the same shape.
 *
 * A pool rather than a single client is required: transactions need a
 * connection to themselves, and issuing `BEGIN` on a connection shared between
 * concurrent requests would interleave unrelated statements into the same
 * transaction.
 */
type PostgresPool = PostgresQueryable & {
    connect(): Promise<PostgresPoolClient>;
};
/**
 * Create or update the `localwebauthn_*` tables. Idempotent — safe to call on
 * every start.
 *
 * ```ts
 * import { Pool } from 'pg';
 * import { migratePostgres, PostgresLocalWebAuthnStore } from '@localwebauthn/server/postgres';
 *
 * const pool = new Pool({ connectionString: process.env.DATABASE_URL });
 * await migratePostgres(pool);
 * const store = new PostgresLocalWebAuthnStore(pool);
 * ```
 */
declare function migratePostgres(pool: PostgresPool, now?: number): Promise<void>;
/**
 * {@link LocalWebAuthnStore} backed by PostgreSQL.
 *
 * Like the SQLite adapter and unlike D1, every multi-statement operation runs
 * inside a real transaction, so partial writes cannot be observed or left
 * behind.
 */
declare class PostgresLocalWebAuthnStore implements LocalWebAuthnStore {
    #private;
    constructor(pool: PostgresPool);
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

export { PostgresLocalWebAuthnStore, type PostgresPool, type PostgresPoolClient, type PostgresQueryResult, type PostgresQueryable, migratePostgres };
