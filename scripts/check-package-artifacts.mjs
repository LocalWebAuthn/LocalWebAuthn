/**
 * Assert what each published tarball actually contains.
 *
 * `npm pack --dry-run` exiting 0 proves nothing: npm silently omits a path listed
 * in `files` that does not exist, which is exactly how `@localwebauthn/client`
 * came within one release of publishing with no LICENSE. This inspects the real
 * file list instead — every declared entry present, every export resolvable, and
 * nothing shipped that should not be.
 *
 * Run through `npm run check:artifacts` (part of `release:check`).
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const PACKAGES = ['server', 'browser', 'client'];

/** Files that must never ship, as [description, predicate] pairs. */
const FORBIDDEN = [
  ['source maps', (path) => path.endsWith('.map')],
  [
    'tests',
    (path) => /(?:^|\/)(?:tests?|__tests__)\//u.test(path) || /\.test\.[cm]?[jt]s$/u.test(path),
  ],
  ['test fixtures', (path) => /(?:^|\/)fixtures?\//u.test(path)],
  ['coverage output', (path) => path.startsWith('coverage/')],
  ['TypeScript sources', (path) => path.startsWith('src/')],
  ['environment files', (path) => /(?:^|\/)\.env/u.test(path)],
  ['npm credentials', (path) => /(?:^|\/)\.npmrc$/u.test(path)],
  ['editor or OS cruft', (path) => /(?:^|\/)(?:\.DS_Store|\.idea|\.vscode)/u.test(path)],
];

/** A tarball larger than this is a mistake worth looking at, not a release. */
const MAX_UNPACKED_BYTES = 2_000_000;

const failures = [];

function fail(packageName, message) {
  failures.push(`${packageName}: ${message}`);
}

/** Every path a package's `exports` map points at, flattened. */
function exportTargets(exports) {
  if (typeof exports === 'string') {
    return [exports];
  }
  if (exports === null || typeof exports !== 'object') {
    return [];
  }
  return Object.values(exports).flatMap((value) => exportTargets(value));
}

for (const name of PACKAGES) {
  const directory = join('packages', name);
  const manifest = JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'));
  const label = manifest.name;

  // `--json` reports the exact file list npm would publish.
  const output = execFileSync(
    'npm',
    ['pack', '--dry-run', '--json', '--workspace', manifest.name],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const [packed] = JSON.parse(output);
  const paths = packed.files.map((file) => file.path);

  if (packed.name !== manifest.name) {
    fail(label, `tarball claims to be ${packed.name}`);
  }
  if (packed.version !== manifest.version) {
    fail(label, `tarball is version ${packed.version}, workspace says ${manifest.version}`);
  }

  // Every entry in `files` must have actually produced content. This is the
  // missing-LICENSE check: npm drops a non-existent path without complaint.
  for (const declared of manifest.files ?? []) {
    const matched = paths.some((path) => path === declared || path.startsWith(`${declared}/`));
    if (!matched) {
      fail(label, `files declares "${declared}" but the tarball has nothing for it`);
    }
  }

  // Both halves of every export: the module and its declarations. A package that
  // ships JavaScript without types typechecks as `any` in a consumer.
  for (const target of exportTargets(manifest.exports ?? {})) {
    const relative = target.replace(/^\.\//u, '');
    if (!paths.includes(relative)) {
      fail(label, `exports points at "${target}", which the tarball does not contain`);
    }
    if (!existsSync(join(directory, relative))) {
      fail(label, `exports points at "${target}", which is missing on disk — build first?`);
    }
  }
  for (const key of ['main', 'types']) {
    const target = manifest[key];
    if (target && !paths.includes(target.replace(/^\.\//u, ''))) {
      fail(label, `${key} points at "${target}", which the tarball does not contain`);
    }
  }

  for (const [description, matches] of FORBIDDEN) {
    const offenders = paths.filter((path) => matches(path));
    if (offenders.length > 0) {
      fail(label, `ships ${description}: ${offenders.slice(0, 5).join(', ')}`);
    }
  }

  // Migrations belong to the server package only.
  const migrations = paths.filter((path) => path.startsWith('migrations/'));
  if (name !== 'server' && migrations.length > 0) {
    fail(label, `ships migrations, which only the server package should: ${migrations.join(', ')}`);
  }

  if (packed.unpackedSize > MAX_UNPACKED_BYTES) {
    fail(label, `unpacked size ${packed.unpackedSize} exceeds ${MAX_UNPACKED_BYTES}`);
  }

  const summary = `${label}@${packed.version}: ${String(paths.length)} files, ${String(packed.unpackedSize)} bytes unpacked`;
  console.log(failures.length === 0 ? `  ok  ${summary}` : `      ${summary}`);
}

if (failures.length > 0) {
  console.error('\nPackage artifact checks failed:');
  for (const failure of failures) {
    console.error(`  - ${failure}`);
  }
  process.exit(1);
}

console.log(`\nAll ${String(PACKAGES.length)} package artifacts contain what they declare.`);
