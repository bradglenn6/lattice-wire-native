import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const addonPath = path.resolve(__dirname, '..', 'build', 'Release', 'lattice_wire_native.node');

const isAsanRun = Boolean(process.env.ASAN_OPTIONS || process.env.LD_PRELOAD?.includes('asan'));

test(
  'secure secret finalizer releases locked pages after the handle is collected',
  { skip: process.platform !== 'linux' || isAsanRun },
  () => {
    const script = `
      import assert from 'node:assert/strict';
      import fs from 'node:fs';

      const mod = { exports: {} };
      process.dlopen(mod, ${JSON.stringify(addonPath)});
      const addon = mod.exports;

      function readVmLckKb() {
        const status = fs.readFileSync('/proc/self/status', 'utf8');
        const match = status.match(/^VmLck:\\s+(\\d+)\\s+kB$/m);
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

    execFileSync(process.execPath, ['--expose-gc', '--input-type=module', '-e', script], {
      stdio: 'pipe',
      encoding: 'utf8'
    });
  }
);
