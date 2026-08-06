import { describe, expect, it } from 'vitest';

import { isD1TransactionGuardFailure } from '../../packages/server/src/d1.js';

describe('isD1TransactionGuardFailure', () => {
  it('recognizes the dedicated guard table in the error text', () => {
    expect(
      isD1TransactionGuardFailure(
        new Error('D1_ERROR: CHECK constraint failed: localwebauthn_transaction_guard'),
      ),
    ).toBe(true);
    expect(
      isD1TransactionGuardFailure(
        'SQLITE_CONSTRAINT: CHECK constraint failed: localwebauthn_transaction_guard.value',
      ),
    ).toBe(true);
  });

  it('recognizes the guard CHECK expression without the table name', () => {
    expect(isD1TransactionGuardFailure(new Error('CHECK constraint failed: value = 1'))).toBe(true);
    expect(isD1TransactionGuardFailure(new Error('CHECK constraint failed: value'))).toBe(true);
  });

  it('does not treat other CHECK or storage faults as guard trips', () => {
    // Schema CHECK on credentials.counter — must propagate as a real fault.
    expect(isD1TransactionGuardFailure(new Error('CHECK constraint failed: counter >= 0'))).toBe(
      false,
    );
    expect(
      isD1TransactionGuardFailure(
        new Error('UNIQUE constraint failed: localwebauthn_credentials.id'),
      ),
    ).toBe(false);
    expect(isD1TransactionGuardFailure(new Error('D1_ERROR: network timeout'))).toBe(false);
    expect(isD1TransactionGuardFailure(new Error('CHECK constraint failed'))).toBe(false);
    expect(isD1TransactionGuardFailure({ message: 'something else' })).toBe(false);
  });
});
