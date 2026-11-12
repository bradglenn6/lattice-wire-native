import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';

import {
  OneRttSession,
  SlidingReplayWindow,
} from '../lib/crypto/OneRttSession.js';

const require = createRequire(import.meta.url);
const addon = require('../build/Release/lattice_wire_native.node');

function createFakeAddon() {
  const nonces = [];
  let openedPlaintext;
  return {
    nonces,
    get openedPlaintext() {
      return openedPlaintext;
    },
    aeadLock(_key, nonce, plaintext) {
      nonces.push(Buffer.from(nonce));
      return Buffer.from(plaintext);
    },
    aeadUnlock(_key, _nonce, sealed) {
      if (sealed[0] === 0xff) {
        throw new Error('authentication failed');
      }
      openedPlaintext = Buffer.from(sealed);
      return openedPlaintext;
    },
    aeadUnlockInPlace(_key, _nonce, buffer) {
      return { buffer, plaintextLength: buffer.length };
    },
    destroySecret() {},
  };
}

function makeHeader(ciphertext) {
  const header = Buffer.alloc(812);
  header.writeUInt32BE(0x4c573031, 0);
  header.writeUInt32BE(0x01020304, 4);
  header.writeBigUInt64BE(1n, 8);
  Buffer.alloc(16, 0xaa).copy(header, 16);
  Buffer.alloc(12, 0x42).copy(header, 32);
  ciphertext.copy(header, 44);
  return header;
}

test('SlidingReplayWindow allows reordering but rejects duplicates and stale values', () => {
  const window = new SlidingReplayWindow();
  assert.equal(window.inspect(4n), true);
  assert.equal(window.commit(4n), true);
  assert.equal(window.commit(6n), true);
  assert.equal(window.commit(5n), true);
  assert.equal(window.inspect(5n), false);
  assert.equal(window.inspect(3n), true);
  assert.equal(window.commit(3n), true);
  assert.equal(window.inspect(3n), false);
  assert.equal(window.commit(70n), true);
  assert.equal(window.inspect(6n), false);
  assert.equal(window.inspect(-1n), false);
  assert.equal(window.inspect(1), false);
  window.reset();
  assert.equal(window.inspect(5n), true);
});

test('native 1-RTT state bindings seal, authenticate, reset, and exhaust sequence numbers', () => {
  const key = Buffer.alloc(32, 0x19);
  const nonce = Buffer.alloc(12, 0x42);
  const aad = Buffer.from([1, 2, 3]);
  const txState = addon.createOneRttState(nonce);
  const rxState = addon.createOneRttState(nonce);
  try {
    const plaintext = Buffer.from('native state frame');
    const { sequenceNumber, sealed } = addon.sealOneRttFrame(
      key,
      txState,
      plaintext,
      aad,
    );
    assert.equal(sequenceNumber, 0n);
    assert.deepEqual(
      addon.openOneRttFrame(key, rxState, sequenceNumber, sealed, aad),
      plaintext,
    );
    assert.throws(
      () => addon.openOneRttFrame(key, rxState, sequenceNumber, sealed, aad),
      { code: 'ERR_REPLAY_DETECTED' },
    );
    addon.resetOneRttReplayWindow(rxState);
    assert.deepEqual(
      addon.openOneRttFrame(key, rxState, sequenceNumber, sealed, aad),
      plaintext,
    );

    const next = addon.sealOneRttFrame(key, txState, plaintext, aad);
    const inPlace = Buffer.from(next.sealed);
    const opened = addon.openOneRttFrameInPlace(
      key,
      rxState,
      next.sequenceNumber,
      inPlace,
      aad,
    );
    assert.deepEqual(
      opened.buffer.subarray(0, opened.plaintextLength),
      plaintext,
    );
    assert.deepEqual(
      inPlace.subarray(opened.plaintextLength),
      Buffer.alloc(16),
    );
  } finally {
    addon.destroyOneRttState(txState);
    addon.destroyOneRttState(txState);
    addon.destroyOneRttState(rxState);
    addon.destroyOneRttState(rxState);
  }
  assert.throws(
    () => addon.sealOneRttFrame(key, txState, Buffer.alloc(0)),
    /already been destroyed/i,
  );

  const terminalState = addon.createOneRttState(nonce, 0xffffffffffffffffn);
  try {
    assert.equal(
      addon.sealOneRttFrame(key, terminalState, Buffer.alloc(0)).sequenceNumber,
      0xffffffffffffffffn,
    );
    assert.throws(
      () => addon.sealOneRttFrame(key, terminalState, Buffer.alloc(0)),
      /exhausted/i,
    );
  } finally {
    addon.destroyOneRttState(terminalState);
  }
});

test('OneRttSession uses unique monotonic nonces and commits only authenticated packets', () => {
  const fakeAddon = createFakeAddon();
  const key = Buffer.alloc(32, 0x33);
  const session = new OneRttSession(fakeAddon, key, {
    baseNonce: Buffer.alloc(12, 0x42),
  });
  try {
    const pkt0 = session.seal(Buffer.from([0]));
    const pkt1 = session.seal(Buffer.from([1]));
    assert.equal(pkt0.sequenceNumber, 0n);
    assert.equal(pkt1.sequenceNumber, 1n);
    assert.notDeepEqual(fakeAddon.nonces[0], fakeAddon.nonces[1]);
    assert.equal(fakeAddon.nonces[0].readBigUInt64BE(4), 0x4242424242424242n);
    assert.equal(fakeAddon.nonces[1].readBigUInt64BE(4), 0x4242424242424243n);

    assert.throws(
      () => session.open(500n, Buffer.from([0xff])),
      /authentication failed/,
    );
    assert.deepEqual(session.open(1n, pkt1.sealed), pkt1.sealed);
    assert.deepEqual(session.openInPlace(0n, Buffer.from(pkt0.sealed)).buffer, pkt0.sealed);
    assert.throws(
      () => session.open(0n, pkt0.sealed),
      { code: 'ERR_REPLAY_DETECTED' },
    );
    assert.equal(session.nextTxSequence, 2n);
  } finally {
    session.destroy();
  }
  assert.deepEqual(key, Buffer.alloc(32));
  assert.equal(session.isDisposed, true);
  assert.throws(() => session.seal(Buffer.alloc(0)), { code: 'ERR_SESSION_DESTROYED' });
});

test('OneRttSession erases plaintext if replay-state commit fails', () => {
  const fakeAddon = createFakeAddon();
  const replayWindow = {
    inspect() {
      return true;
    },
    commit() {
      return false;
    },
  };
  const session = new OneRttSession(fakeAddon, Buffer.alloc(32), {
    replayWindow,
    ownsKey: false,
  });
  try {
    assert.throws(
      () => session.open(1n, Buffer.from([1])),
      { code: 'ERR_REPLAY_DETECTED' },
    );
    assert.deepEqual(fakeAddon.openedPlaintext, Buffer.alloc(1));

    const inPlace = Buffer.from([2, 3]);
    assert.throws(
      () => session.openInPlace(2n, inPlace),
      { code: 'ERR_REPLAY_DETECTED' },
    );
    assert.deepEqual(inPlace, Buffer.alloc(2));
  } finally {
    session.destroy();
  }
});

test('OneRttSession round-trips derived secure handles without exposing the key to V8', (t) => {
  let serverSecretKey;
  let clientSharedSecret;
  let serverSharedSecret;
  let clientKeyHandle;
  let serverKeyHandle;
  let destroyedClientKeyHandle;
  let clientSession;
  let serverSession;
  try {
    const keypair = addon.generateMlKem512Keypair({ secureHandle: true });
    serverSecretKey = keypair.secretKey;
    const encapsulated = addon.encapsulateMlKem512(
      keypair.publicKey,
      { secureHandle: true },
    );
    clientSharedSecret = encapsulated.sharedSecret;
    serverSharedSecret = addon.decapsulateMlKem512(
      encapsulated.ciphertext,
      serverSecretKey,
      { secureHandle: true },
    );
    const header = makeHeader(encapsulated.ciphertext);
    clientKeyHandle = addon.deriveZeroRttKey(
      clientSharedSecret,
      header,
      { secureHandle: true },
    );
    serverKeyHandle = addon.deriveZeroRttKey(
      serverSharedSecret,
      header,
      { secureHandle: true },
    );

    addon.destroySecret(clientSharedSecret);
    clientSharedSecret = null;
    addon.destroySecret(serverSharedSecret);
    serverSharedSecret = null;
    addon.destroySecret(serverSecretKey);
    serverSecretKey = null;

    const baseNonce = Buffer.alloc(12, 0x55);
    destroyedClientKeyHandle = clientKeyHandle;
    clientSession = new OneRttSession(addon, clientKeyHandle, { baseNonce });
    clientKeyHandle = null;
    serverSession = new OneRttSession(addon, serverKeyHandle, { baseNonce });
    serverKeyHandle = null;

    const aad = Buffer.from([1, 2, 3, 4]);
    const message0 = Buffer.from('frame-0-payload');
    const message1 = Buffer.from('frame-1-payload');
    const packet0 = clientSession.seal(message0, aad);
    const packet1 = clientSession.seal(message1, aad);
    assert.equal(packet0.sequenceNumber, 0n);
    assert.equal(packet1.sequenceNumber, 1n);

    assert.deepEqual(serverSession.open(packet1.sequenceNumber, packet1.sealed, aad), message1);

    const forged = Buffer.from(packet0.sealed);
    forged[0] ^= 0xff;
    assert.throws(
      () => serverSession.open(500n, forged, aad),
      /authentication failed/i,
    );

    const inPlace = Buffer.from(packet0.sealed);
    const opened = serverSession.openInPlace(packet0.sequenceNumber, inPlace, aad);
    assert.deepEqual(opened.buffer.subarray(0, opened.plaintextLength), message0);
    assert.throws(
      () => serverSession.open(0n, packet0.sealed, aad),
      { code: 'ERR_REPLAY_DETECTED' },
    );
    assert.throws(
      () => serverSession.openInPlace(1n, Buffer.from(packet1.sealed), aad),
      { code: 'ERR_REPLAY_DETECTED' },
    );
  } catch (error) {
    if (/secure memory|memory-lock limits|core dumps/i.test(error.message)) {
      t.skip(`The operating system did not permit secure memory allocation: ${error.message}`);
      return;
    }
    throw error;
  } finally {
    clientSession?.destroy();
    serverSession?.destroy();
    for (const handle of [
      clientKeyHandle,
      serverKeyHandle,
      clientSharedSecret,
      serverSharedSecret,
      serverSecretKey,
    ]) {
      if (handle !== undefined && handle !== null) {
        addon.destroySecret(handle);
      }
    }
  }

  assert.throws(
    () => addon.aeadLock(
      destroyedClientKeyHandle,
      Buffer.alloc(12),
      Buffer.from('after-destroy'),
    ),
  );
});
