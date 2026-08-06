import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    exclude: [
      ...configDefaults.exclude,
      'examples/demo/e2e/**',
      // Own vitest config / workspace package tests.
      'examples/channels/**',
      'examples/channels-node/**',
      'examples/channels-cf/**',
      'examples/starter-hono/**',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['packages/*/src/**/*.ts'],
      // Re-export barrels have no statements of their own.
      exclude: ['packages/*/src/index.ts'],
      thresholds: {
        statements: 80,
        branches: 70,
        functions: 80,
        lines: 80,
      },
    },
  },
});
