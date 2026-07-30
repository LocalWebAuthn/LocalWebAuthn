import { existsSync, unlinkSync } from 'node:fs';

import { demoDatabasePath } from './database';

const path = demoDatabasePath();
for (const suffix of ['', '-shm', '-wal']) {
  const file = `${path}${suffix}`;
  if (existsSync(file)) {
    unlinkSync(file);
  }
}
console.log(`Reset ${path}`);
