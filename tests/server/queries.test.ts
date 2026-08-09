import { describe, expect, it } from 'vitest';

import {
  D1_SQL,
  POSTGRES_SQL,
  SQL,
  toPositionalPlaceholders,
} from '../../packages/server/src/queries.js';

const allStatements = { ...SQL, ...D1_SQL, ...POSTGRES_SQL };

describe('toPositionalPlaceholders', () => {
  it('numbers placeholders from one, in order', () => {
    expect(toPositionalPlaceholders('SELECT ? , ? , ?')).toBe('SELECT $1 , $2 , $3');
  });

  it('leaves statements without placeholders untouched', () => {
    expect(toPositionalPlaceholders('DELETE FROM t')).toBe('DELETE FROM t');
  });

  it('rewrites every placeholder in each shared statement', () => {
    for (const [name, sql] of Object.entries(SQL)) {
      const converted = toPositionalPlaceholders(sql);
      expect(converted, `${name} still contains a '?' placeholder`).not.toContain('?');
      const expected = (sql.match(/\?/gu) ?? []).length;
      const produced = (converted.match(/\$\d+/gu) ?? []).length;
      expect(produced, `${name} placeholder count changed`).toBe(expected);
    }
  });
});

describe('statement hygiene', () => {
  /**
   * toPositionalPlaceholders rewrites every '?' it finds, so a '?' inside a
   * string literal would be silently corrupted. No statement has one today;
   * this guards that precondition rather than trusting it.
   */
  it('never puts a placeholder character inside a string literal', () => {
    for (const [name, sql] of Object.entries(allStatements)) {
      for (const literal of sql.match(/'[^']*'/gu) ?? []) {
        expect(literal, `${name} has a '?' inside the literal ${literal}`).not.toContain('?');
      }
    }
  });

  it('only ever targets localwebauthn_-prefixed tables', () => {
    // The package must never read or write a host application's own tables.
    // `DO UPDATE SET` in an upsert is not a table reference — the target was
    // already named by the INSERT — so exclude it rather than loosening the guard.
    const tableReferences = /(?:FROM|JOIN|INTO|(?<!DO\s)UPDATE)\s+([a-z_][a-z0-9_]*)/giu;
    for (const [name, sql] of Object.entries(allStatements)) {
      for (const match of sql.matchAll(tableReferences)) {
        expect(match[1], `${name} references non-LocalWebAuthn table ${match[1]}`).toMatch(
          /^localwebauthn_/u,
        );
      }
    }
  });
});
