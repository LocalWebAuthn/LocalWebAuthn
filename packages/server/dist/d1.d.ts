import { L as LocalWebAuthnStore, a as LocalWebAuthnDpopStore, E as EnrollmentGrantRecord, b as EnrollmentSession, C as ChallengeRecord, c as ChallengeKind, d as ConsumedChallenge, e as Credential, f as CompleteRegistrationInput, g as CompleteAuthenticationInput, S as SessionIdentity, R as RevokedSession, h as RevokeCredentialResult, i as CleanupResult } from './types-BkXhC9Te.js';
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
/**
 * Create or upgrade the `localwebauthn_*` tables. Idempotent — safe to call on
 * every deploy.
 *
 * Version-aware, exactly like {@link migrateSqlite} and {@link migratePostgres}:
 * it reads the stored schema version and applies only what is missing. The
 * previous implementation ran the current full schema blind, so on a released v1
 * database the `CREATE TABLE IF NOT EXISTS` statements were no-ops, the v1→v2
 * `ALTER TABLE`s never ran, and the first index over a v2-only column
 * (`localwebauthn_credential_kind_idx`) failed against a column that did not
 * exist — a v1 D1 deployment could not upgrade at all.
 *
 * A D1 `batch()` is one implicit transaction: a failing statement aborts and
 * rolls back the whole sequence
 * (https://developers.cloudflare.com/d1/worker-api/d1-database/). So the upgrade
 * DDL and the version stamp that records it commit together or not at all — a
 * half-applied schema is never observable.
 */
declare function migrateD1(database: D1DatabaseLike, now?: number): Promise<void>;
/**
 * {@link LocalWebAuthnStore} backed by Cloudflare D1.
 *
 * Multi-statement operations run as a `batch()`, which D1 executes as one
 * transaction: a failing statement aborts and rolls the whole sequence back
 * (https://developers.cloudflare.com/d1/worker-api/d1-database/). Every step that
 * must affect exactly one row is followed by a guard statement whose CHECK fails
 * the batch otherwise, so an unauthorized write rolls the batch back rather than
 * committing partially. See the D1 section of `SECURITY.md`. Schedule
 * {@link D1LocalWebAuthnStore.cleanup} to reap expired grants, challenges, and
 * sessions.
 */
declare class D1LocalWebAuthnStore implements LocalWebAuthnStore, LocalWebAuthnDpopStore {
    #private;
    constructor(database: D1DatabaseLike);
    replaceEnrollmentGrant(record: EnrollmentGrantRecord): Promise<string[]>;
    revokePendingEnrollmentGrants(userId: string, now: number, credentialKind: string | null): Promise<string[]>;
    exchangeEnrollment(tokenHash: Uint8Array, sessionHash: Uint8Array, sessionExpiresAt: number, now: number): Promise<EnrollmentSession | null>;
    resolveEnrollmentSession(sessionHash: Uint8Array, now: number): Promise<EnrollmentSession | null>;
    createChallenge(record: ChallengeRecord): Promise<boolean>;
    consumeChallenge(idHash: Uint8Array, kind: ChallengeKind, now: number): Promise<ConsumedChallenge | null>;
    listCredentials(userId: string, includeRevoked?: boolean): Promise<Credential[]>;
    getCredential(credentialId: string): Promise<Credential | null>;
    credentialAncestry(userId: string, credentialId: string): Promise<Credential[]>;
    credentialDescendants(userId: string, credentialId: string): Promise<Credential[]>;
    completeRegistration(input: CompleteRegistrationInput): Promise<boolean>;
    completeAuthentication(input: CompleteAuthenticationInput): Promise<boolean>;
    resolveSession(idHash: Uint8Array, now: number, idleExpiresBefore: number): Promise<SessionIdentity | null>;
    touchSession(idHash: Uint8Array, now: number): Promise<boolean>;
    revokeSession(idHash: Uint8Array, now: number): Promise<RevokedSession | null>;
    revokeUserSessions(userId: string, now: number, idleExpiresBefore: number, exceptSessionHash?: Uint8Array): Promise<number>;
    revokeCredential(userId: string, credentialId: string, now: number, options?: {
        allowLastCredential?: boolean;
    }): Promise<RevokeCredentialResult>;
    revokeUserAuthentication(userId: string, now: number): Promise<void>;
    cleanup(now: number): Promise<CleanupResult>;
    claimDpopProof(jtiHash: Uint8Array, expiresAt: number): Promise<boolean>;
    revokeLiveCredentialSessions(credentialId: string, now: number, idleExpiresBefore: number, exceptSessionHash?: Uint8Array): Promise<number>;
    claimDpopNonce(slot: number, candidate: string, expiresAt: number): Promise<string>;
    dpopNonces(currentSlot: number, previousSlot: number): Promise<string[]>;
}

export { type D1DatabaseLike, D1LocalWebAuthnStore, type D1PreparedStatementLike, type D1ResultLike, migrateD1 };
