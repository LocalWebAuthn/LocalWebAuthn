import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['**/dist/**', '**/coverage/**', '**/node_modules/**', 'eslint.config.js'],
  },
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/consistent-type-definitions': ['error', 'type'],
      '@typescript-eslint/no-confusing-void-expression': 'off',
      '@typescript-eslint/prefer-optional-chain': 'off',
      '@typescript-eslint/require-await': 'off',
    },
  },
  {
    // The raw-key boundary. `@localwebauthn/client/file-key` is the only module
    // that handles exportable private keys; nothing in the server or browser
    // packages has any business touching it, and a stray import is exactly the kind
    // of thing that survives review.
    files: ['packages/server/**/*.ts', 'packages/browser/**/*.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['**/client/src/file-key*', '@localwebauthn/client/file-key'],
              message:
                'Raw private-key operations must not be reachable from the server or browser packages.',
            },
          ],
        },
      ],
    },
  },
  {
    // Release tooling: plain Node ESM, deliberately outside the TypeScript
    // project, so the type-aware rules have no program to consult. Still linted
    // for ordinary correctness.
    files: ['scripts/**/*.mjs'],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      // Opt out of the project service too, not just the type-aware rules: this
      // file is not in any tsconfig, and the parser would otherwise refuse it.
      parserOptions: { projectService: false, project: null, program: null },
      globals: { console: 'readonly', process: 'readonly' },
    },
  },
  {
    files: ['tests/**/*.ts'],
    rules: {
      '@typescript-eslint/no-unnecessary-type-assertion': 'off',
      '@typescript-eslint/non-nullable-type-assertion-style': 'off',
    },
  },
);
