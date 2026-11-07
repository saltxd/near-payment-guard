// The sandbox binary (neard) exists only for the platforms scripts/ensure-sandbox.mjs lists,
// and the Linux build needs a recent glibc. A stranger on any other machine gets a failed
// `npm ci` or a silently skipped sandbox suite, so the README must say which machines work.
// This keeps the README's list in step with the script.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = join(import.meta.dirname, '..', '..');
const readme = readFileSync(join(root, 'README.md'), 'utf8');
const script = readFileSync(join(root, 'scripts/ensure-sandbox.mjs'), 'utf8');

test('README names every platform ensure-sandbox.mjs supports', () => {
  assert.match(script, /Darwin-arm64/);
  assert.match(script, /Linux-x86_64/);
  assert.match(readme, /macOS on Apple Silicon/);
  assert.match(readme, /Linux on x86_64/);
});

test('README warns that other platforms and old glibc cannot run the sandbox', () => {
  assert.match(readme, /glibc 2\.39/);
  assert.match(readme, /Linux arm64/);
});
