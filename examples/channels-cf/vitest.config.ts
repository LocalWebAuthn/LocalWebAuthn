import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // Miniflare instances take a moment to start workerd.
    testTimeout: 30_000,
  },
});
