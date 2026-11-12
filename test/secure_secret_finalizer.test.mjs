import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const addonPath = fileURLToPath(
  new URL('../build/Release/lattice_wire_native.node', import.meta.url),
);

test('secure secret finalizer releases locked pages after the handle is collected', {
  skip: process.platform !== 'linux'
    ? 'VmLck check requires Linux /proc/self/status'
    : false,
}, () => {
  const script = `
    import assert from 'node:assert/strict';
    import fs from 'node:fs';

    const addon = require(${JSON.stringify(addonPath)});
    function readVmLckKb() {
      const status = fs.readFileSync('/proc/self/status', 'utf8');
      const match = status.match(/^VmLck:\\\\s+(\\\\d+)\\\\s+kB$/m);
      assert.notEqual(match, null, 'Expected VmLck in /proc/self/status');
      return Number.parseInt(match[1], 10);
    }

    const baselineKb = readVmLckKb();
    let handle = addon.allocateSecret(Buffer.alloc(32, 0xa5));
    const allocatedKb = readVmLckKb();
    assert.ok(allocatedKb >= baselineKb + 4, 'Expected one locked page');

    for (let i = 0; i < 3; i += 1) {
      global.gc();
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(readVmLckKb(), allocatedKb, 'A live handle must retain its pages');

    handle = null;
    for (let i = 0; i < 100 && readVmLckKb() !== baselineKb; i += 1) {
      global.gc();
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(readVmLckKb(), baselineKb, 'Collected handle must unlock its pages');
  `;

  execFileSync(
    process.execPath,
    ['--expose-gc', '--input-type=module', '-e', script],
    { encoding: 'utf8', timeout: 15000 },
  );
});
