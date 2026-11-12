import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import test from 'node:test';

import { EpochKeyManager } from '../lib/crypto/EpochKeyManager.js';
import { OneRttSession } from '../lib/crypto/OneRttSession.js';

const require = createRequire(import.meta.url);
const addon = require('../build/Release/lattice_wire_native.node');

function readVmLckKb() {
  if (process.platform !== 'linux') {
    return null;
  }
  const status = fs.readFileSync('/proc/self/status', 'utf8');
  const match = status.match(/^VmLck:\s+(\d+)\s+kB$/m);
  return match === null ? null : Number.parseInt(match[1], 10);
}

test('Linux VmLck tracks secure-handle allocation and deterministic destruction', {
  skip: process.platform !== 'linux'
    ? 'VmLck check requires Linux /proc/self/status'
    : false,
}, () => {
  const baselineKb = readVmLckKb();
  assert.notEqual(baselineKb, null, 'Expected VmLck field in /proc/self/status');

  let handle;
  let manager;
  let secretKey;
  let sharedSecret;
  let session;
  let sessionKeyHandle;
  let pageDeltaKb;

  try {
    const rawSecret = Buffer.alloc(32, 0xaa);
    handle = addon.allocateSecret(rawSecret);
    rawSecret.fill(0);

    const afterAllocKb = readVmLckKb();
    pageDeltaKb = afterAllocKb - baselineKb;
    assert.ok(
      pageDeltaKb >= 4,
      `Expected VmLck to increase by at least 4 kB, got +${pageDeltaKb} kB`,
    );

    addon.destroySecret(handle);
    addon.destroySecret(handle);
    assert.equal(
      readVmLckKb(),
      baselineKb,
      'VmLck must return to baseline immediately after destroySecret',
    );
    handle = null;

    manager = new EpochKeyManager(addon, { initialEpoch: 1 });
    assert.equal(
      readVmLckKb(),
      baselineKb + pageDeltaKb,
      'Initial epoch must lock one allocation',
    );

    manager.rotate(2);
    assert.equal(
      readVmLckKb(),
      baselineKb + (pageDeltaKb * 2),
      'First rotation must lock two allocations',
    );

    manager.rotate(3);
    manager.rotate(4);
    assert.equal(
      readVmLckKb(),
      baselineKb + (pageDeltaKb * 2),
      'EpochKeyManager must stay within two secure allocations',
    );

    manager.expirePrevious();
    assert.equal(
      readVmLckKb(),
      baselineKb + pageDeltaKb,
      'expirePrevious() must immediately release one allocation',
    );
    manager.destroy();
    manager = null;
    assert.equal(
      readVmLckKb(),
      baselineKb,
      'EpochKeyManager.destroy() must restore the baseline',
    );

    const keypair = addon.generateMlKem512Keypair({ secureHandle: true });
    secretKey = keypair.secretKey;
    const encapsulated = addon.encapsulateMlKem512(
      keypair.publicKey,
      { secureHandle: true },
    );
    sharedSecret = encapsulated.sharedSecret;

    const headerAad = Buffer.alloc(812);
    headerAad.writeUInt32BE(0x4c573031, 0);
    headerAad.writeUInt32BE(0x01020304, 4);
    headerAad.writeBigUInt64BE(1n, 8);
    encapsulated.ciphertext.copy(headerAad, 44);

    sessionKeyHandle = addon.deriveZeroRttKey(
      sharedSecret,
      headerAad,
      { secureHandle: true },
    );
    assert.equal(
      readVmLckKb(),
      baselineKb + (pageDeltaKb * 3),
      'Expected three locked KEM and session-key allocations',
    );

    session = new OneRttSession(addon, sessionKeyHandle, {
      baseNonce: headerAad.subarray(32, 44),
      ownsKey: true,
    });
    sessionKeyHandle = null;

    addon.destroySecret(sharedSecret);
    sharedSecret = null;
    addon.destroySecret(secretKey);
    secretKey = null;
    assert.equal(
      readVmLckKb(),
      baselineKb + pageDeltaKb,
      'Destroying handshake handles must leave only the session key locked',
    );

    session.destroy();
    session = null;
    assert.equal(
      readVmLckKb(),
      baselineKb,
      'OneRttSession.destroy() must release its owned session key',
    );
  } finally {
    session?.destroy();
    manager?.destroy();
    for (const secret of [
      handle,
      sharedSecret,
      secretKey,
      sessionKeyHandle,
    ]) {
      if (secret !== undefined && secret !== null) {
        addon.destroySecret(secret);
      }
    }
  }
});
