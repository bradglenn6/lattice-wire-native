import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';

import { EpochKeyManager } from '../lib/crypto/EpochKeyManager.js';

const require = createRequire(import.meta.url);
const addon = require('../build/Release/lattice_wire_native.node');

function createFakeAddon({ failGenerationAt = Infinity } = {}) {
  let nextId = 0;
  let activeAllocations = 0;
  let maximumActiveAllocations = 0;
  let generationCount = 0;
  const destroyed = [];

  return {
    destroyed,
    get activeAllocations() {
      return activeAllocations;
    },
    get maximumActiveAllocations() {
      return maximumActiveAllocations;
    },
    generateMlKem512Keypair(options) {
      assert.deepEqual(options, { secureHandle: true });
      generationCount += 1;
      if (generationCount === failGenerationAt) {
        throw new Error('simulated secure allocation failure');
      }
      activeAllocations += 1;
      maximumActiveAllocations = Math.max(
        maximumActiveAllocations,
        activeAllocations,
      );
      return {
        publicKey: Buffer.from([++nextId]),
        secretKey: { id: nextId },
      };
    },
    destroySecret(handle) {
      if (handle !== null && !destroyed.includes(handle)) {
        destroyed.push(handle);
        activeAllocations -= 1;
      }
    },
  };
}

test('rotates two epochs and destroys the expired secure handle', () => {
  const fakeAddon = createFakeAddon();
  const manager = new EpochKeyManager(fakeAddon, {
    initialEpoch: 10,
    createReplayWindow: (epoch) => ({ epoch }),
  });
  const expiredHandle = manager.resolveEpoch(10).secretKey;

  assert.equal(manager.resolveEpoch(10).replayWindow.epoch, 10);
  manager.rotate(11);
  assert.notEqual(manager.resolveEpoch(10), null);
  assert.notEqual(manager.resolveEpoch(11), null);

  manager.rotate(12);
  assert.equal(manager.resolveEpoch(10), null);
  assert.notEqual(manager.resolveEpoch(11), null);
  assert.notEqual(manager.resolveEpoch(12), null);
  assert.deepEqual(fakeAddon.destroyed, [expiredHandle]);
  assert.equal(fakeAddon.maximumActiveAllocations, 2);

  manager.destroy();
  assert.equal(fakeAddon.activeAllocations, 0);
  assert.equal(manager.isDisposed, true);
  assert.throws(() => manager.getPublicAdvertisement(), /destroyed/i);
});

test('failed rotation preserves the current epoch and stays within two allocations', () => {
  const fakeAddon = createFakeAddon({ failGenerationAt: 3 });
  const manager = new EpochKeyManager(fakeAddon, {
    initialEpoch: 20,
    createReplayWindow: (epoch) => ({ epoch }),
  });

  manager.rotate(21);
  const current = manager.resolveEpoch(21);
  assert.throws(() => manager.rotate(22), /simulated secure allocation failure/);
  assert.equal(manager.getPublicAdvertisement().epoch, 21);
  assert.equal(manager.resolveEpoch(20), null);
  assert.equal(manager.resolveEpoch(21).secretKey, current.secretKey);
  assert.equal(fakeAddon.maximumActiveAllocations, 2);
  assert.equal(fakeAddon.activeAllocations, 1);
  manager.destroy();
  assert.equal(fakeAddon.activeAllocations, 0);
});

test('does not retire an epoch while an ingress lease is active', () => {
  const fakeAddon = createFakeAddon();
  const manager = new EpochKeyManager(fakeAddon, {
    initialEpoch: 30,
    createReplayWindow: (epoch) => ({ epoch }),
  });

  manager.rotate(31);
  const lease = manager.acquireEpoch(30);
  assert.equal(lease.epoch, 30);
  assert.throws(() => manager.rotate(32), /active leases/);
  assert.equal(manager.resolveEpoch(30).secretKey, lease.secretKey);

  lease.release();
  lease.release();
  manager.rotate(32);
  assert.equal(manager.resolveEpoch(30), null);
  manager.destroy();
  assert.equal(fakeAddon.activeAllocations, 0);
});

test('defers destruction until leases release after manager disposal', () => {
  const fakeAddon = createFakeAddon();
  const manager = new EpochKeyManager(fakeAddon, {
    createReplayWindow: (epoch) => ({ epoch }),
  });
  const lease = manager.acquireEpoch(1);

  manager.destroy();
  assert.equal(fakeAddon.activeAllocations, 1);
  assert.throws(() => manager.acquireEpoch(1), /destroyed/i);

  lease.release();
  assert.equal(fakeAddon.activeAllocations, 0);
});

test('rejects invalid epochs and cleans up if replay-window creation fails', () => {
  assert.throws(
    () => new EpochKeyManager(createFakeAddon(), { initialEpoch: -1 }),
    /uint32/,
  );
  const fakeAddon = createFakeAddon();
  assert.throws(
    () => new EpochKeyManager(fakeAddon, {
      createReplayWindow() {
        throw new Error('replay initialization failed');
      },
    }),
    /replay initialization failed/,
  );
  assert.equal(fakeAddon.activeAllocations, 0);
});

test('integrates secure epoch handles with the native zero-RTT binding', (t) => {
  let manager;
  try {
    manager = new EpochKeyManager(addon);
  } catch (error) {
    if (/secure memory|memory-lock limits|core dumps/i.test(error.message)) {
      t.skip(`The operating system did not permit secure memory allocation: ${error.message}`);
      return;
    }
    throw error;
  }

  const advertisement = manager.getPublicAdvertisement();
  assert.equal(advertisement.publicKey.byteLength, 800);
  const slot = manager.resolveEpoch(advertisement.epoch);
  assert.equal(typeof slot.secretKey, 'object');
  assert.ok(slot.replayWindow);
  manager.destroy();
});

test('supports explicit disposal and idempotent destruction', () => {
  const fakeAddon = createFakeAddon();
  const manager = new EpochKeyManager(fakeAddon, {
    createReplayWindow: (epoch) => ({ epoch }),
  });
  manager[Symbol.dispose]();
  manager.destroy();
  assert.equal(fakeAddon.activeAllocations, 0);
  assert.equal(manager.isDisposed, true);
});
