import { defineConfig, devices } from '@playwright/test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = fileURLToPath(new URL('../..', import.meta.url));

export default defineConfig({
  testDir: 'e2e',
  outputDir: '../../test-results/demo',
  reporter: 'list',
  workers: 1,
  use: {
    baseURL: 'http://localhost:4173',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'npm run demo:reset && npm run demo',
    cwd: repositoryRoot,
    env: {
      DEMO_DATABASE_PATH: '.data/e2e.db',
      DEMO_BOOTSTRAP_EMAIL: 'admin@example.test',
      DEMO_BOOTSTRAP_NAME: 'Demo Administrator',
    },
    url: 'http://localhost:4173/api/health',
    reuseExistingServer: false,
    timeout: 30_000,
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1365, height: 860 },
      },
    },
  ],
});
