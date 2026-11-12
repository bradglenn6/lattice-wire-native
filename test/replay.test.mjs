import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import test from 'node:test';

test('native two-phase replay window tests', () => {
  const executable = join(
    'build',
    'Release',
    process.platform === 'win32' ? 'anti_replay_test.exe' : 'anti_replay_test',
  );
  const output = execFileSync(executable, { encoding: 'utf8' });
  assert.match(output, /tests passed/);
});
