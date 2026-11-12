import assert from 'node:assert/strict';
import { createCipheriv, createHash, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import test from 'node:test';

const require = createRequire(import.meta.url);
const native = require('../build/Release/lattice_wire_native.node');

function createAuthenticatedFrame({ publicKey, sequenceNumber, plaintext }) {
  const frame = Buffer.alloc(828 + plaintext.length);
  frame.writeUInt16BE(0x5A4C, 0);
  frame.writeUInt8(1, 2);
  frame.writeUInt32BE(23, 4);
  frame.writeBigUInt64BE(sequenceNumber, 8);
  frame.writeBigUInt64BE(0x0102030405060708n, 16);
  frame.writeUInt16BE(plaintext.length, 24);
  frame.writeUInt16BE(32, 26);

  const { ciphertext, sharedSecret } = native.encapsulateMlKem512(publicKey);
  ciphertext.copy(frame, 32);
  const nonce = randomBytes(12);
  nonce.copy(frame, 800);
  const kdfInput = Buffer.concat([
    Buffer.from('ZeroLabz-LatticeWire-v1', 'ascii'),
    sharedSecret,
    Buffer.from('0102030405060708', 'hex'),
    Buffer.from('00000017', 'hex'),
    nonce,
  ]);
  const key = createHashShake256(kdfInput);
  sharedSecret.fill(0);
  kdfInput.fill(0);

  const cipher = createCipheriv('chacha20-poly1305', key, nonce, {
    authTagLength: 16,
  });
  cipher.setAAD(frame.subarray(0, 812), {
    plaintextLength: plaintext.length,
  });
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  encrypted.copy(frame, 812);
  cipher.getAuthTag().copy(frame, 812 + plaintext.length);
  key.fill(0);
  return frame;
}

function createHashShake256(input) {
  return createHash('shake256', { outputLength: 32 }).update(input).digest();
}

function createHeaderAad({ ciphertext, sequenceNumber, plaintextLength }) {
  const header = Buffer.alloc(812);
  header.writeUInt16BE(0x5A4C, 0);
  header.writeUInt8(1, 2);
  header.writeUInt32BE(23, 4);
  header.writeBigUInt64BE(sequenceNumber, 8);
  header.writeBigUInt64BE(0x0102030405060708n, 16);
  header.writeUInt16BE(plaintextLength, 24);
  header.writeUInt16BE(32, 26);
  ciphertext.copy(header, 32);
  randomBytes(12).copy(header, 800);
  return header;
}

test('native zero-RTT ML-KEM/AEAD/replay integration', () => {
  const executable = join(
    'build',
    'Release',
    process.platform === 'win32'
      ? 'zero_rtt_engine_test.exe'
      : 'zero_rtt_engine_test',
  );
  const output = execFileSync(executable, { encoding: 'utf8' });
  assert.match(output, /Zero-RTT ML-KEM\/AEAD ingestion tests passed/);
});

test('decrypts the payload in the original Buffer only after authentication', () => {
  const { publicKey, secretKey } = native.generateMlKem512Keypair();
  const plaintext = Buffer.from('in-place authenticated payload');
  const frame = createAuthenticatedFrame({
    publicKey,
    sequenceNumber: 75n,
    plaintext,
  });
  const originalCiphertext = Buffer.from(frame.subarray(812, 812 + plaintext.length));
  const replayWindow = native.createReplayWindow();

  const result = native.processZeroRttDatagramInPlace(
    frame,
    secretKey,
    0x0102030405060708n,
    replayWindow,
  );
  assert.equal(result.status, 'FRAME_AUTHENTICATED');
  assert.equal(result.frame, frame);
  assert.equal(result.plaintextOffset, 812);
  assert.equal(result.plaintextLength, plaintext.length);
  assert.deepEqual(
    frame.subarray(result.plaintextOffset, result.plaintextOffset + result.plaintextLength),
    plaintext,
  );
  assert.notDeepEqual(frame.subarray(812, 812 + plaintext.length), originalCiphertext);
  assert.throws(
    () => native.processZeroRttDatagramInPlace(
      frame,
      secretKey,
      0x0102030405060708n,
      replayWindow,
    ),
    /replay window rejected/i,
  );
  secretKey.fill(0);
});

test('in-place authentication failure preserves ciphertext and does not commit replay', () => {
  const { publicKey, secretKey } = native.generateMlKem512Keypair();
  const frame = createAuthenticatedFrame({
    publicKey,
    sequenceNumber: 76n,
    plaintext: Buffer.from('leave ciphertext untouched'),
  });
  const damaged = Buffer.from(frame);
  damaged[damaged.length - 1] ^= 0x80;
  const before = Buffer.from(damaged);
  const replayWindow = native.createReplayWindow();

  assert.throws(
    () => native.processZeroRttDatagramInPlace(
      damaged,
      secretKey,
      0x0102030405060708n,
      replayWindow,
    ),
    /authentication failed/i,
  );
  assert.deepEqual(damaged, before);
  const result = native.processZeroRttDatagramInPlace(
    frame,
    secretKey,
    0x0102030405060708n,
    replayWindow,
  );
  assert.equal(result.status, 'FRAME_AUTHENTICATED');
  secretKey.fill(0);
});

test('supports an authenticated empty payload in place', () => {
  const { publicKey, secretKey } = native.generateMlKem512Keypair();
  const frame = createAuthenticatedFrame({
    publicKey,
    sequenceNumber: 77n,
    plaintext: Buffer.alloc(0),
  });
  const result = native.processZeroRttDatagramInPlace(
    frame,
    secretKey,
    0x0102030405060708n,
    native.createReplayWindow(),
  );
  assert.equal(result.frame, frame);
  assert.equal(result.plaintextOffset, 812);
  assert.equal(result.plaintextLength, 0);
  secretKey.fill(0);
});

test('uses and explicitly destroys a locked native secret allocation', (t) => {
  const { publicKey, secretKey } = native.generateMlKem512Keypair();
  let secureSecret;
  try {
    secureSecret = native.allocateSecret(secretKey);
  } catch (error) {
    if (/secure memory|memory-lock limits|core dumps/i.test(error.message)) {
      t.skip(`The operating system did not permit secure memory allocation: ${error.message}`);
      secretKey.fill(0);
      return;
    }
    throw error;
  }
  secretKey.fill(0);

  const frame = createAuthenticatedFrame({
    publicKey,
    sequenceNumber: 78n,
    plaintext: Buffer.from('native locked secret'),
  });
  const replayWindow = native.createReplayWindow();
  const result = native.processZeroRttDatagramInPlace(
    frame,
    secureSecret,
    0x0102030405060708n,
    replayWindow,
  );
  assert.equal(result.status, 'FRAME_AUTHENTICATED');
  assert.equal(result.frame, frame);

  assert.equal(native.destroySecret(secureSecret), undefined);
  assert.equal(native.destroySecret(secureSecret), undefined);
  assert.throws(
    () => native.processZeroRttDatagramInPlace(
      createAuthenticatedFrame({
        publicKey,
        sequenceNumber: 79n,
        plaintext: Buffer.from('after destruction'),
      }),
      secureSecret,
      0x0102030405060708n,
      native.createReplayWindow(),
    ),
    /already been destroyed/i,
  );
});

test('generates ML-KEM secret keys directly into a secure handle', (t) => {
  let keypair;
  try {
    keypair = native.generateMlKem512Keypair({ secureHandle: true });
  } catch (error) {
    if (/secure memory|memory-lock limits|core dumps/i.test(error.message)) {
      t.skip(`The operating system did not permit secure memory allocation: ${error.message}`);
      return;
    }
    throw error;
  }

  const { publicKey, secretKey } = keypair;
  assert.equal(Buffer.isBuffer(publicKey), true);
  assert.equal(publicKey.byteLength, 800);
  assert.equal(Buffer.isBuffer(secretKey), false);
  assert.equal(typeof secretKey, 'object');

  const frame = createAuthenticatedFrame({
    publicKey,
    sequenceNumber: 80n,
    plaintext: Buffer.from('direct secure keypair'),
  });
  const result = native.processZeroRttDatagramInPlace(
    frame,
    secretKey,
    0x0102030405060708n,
    native.createReplayWindow(),
  );
  assert.equal(result.status, 'FRAME_AUTHENTICATED');
  assert.deepEqual(
    frame.subarray(result.plaintextOffset, result.plaintextOffset + result.plaintextLength),
    Buffer.from('direct secure keypair'),
  );

  assert.equal(native.destroySecret(secretKey), undefined);
  assert.throws(
    () => native.processZeroRttDatagramInPlace(
      createAuthenticatedFrame({
        publicKey,
        sequenceNumber: 81n,
        plaintext: Buffer.from('after destruction'),
      }),
      secretKey,
      0x0102030405060708n,
      native.createReplayWindow(),
    ),
    /already been destroyed/i,
  );
});

test('exports the zero-RTT binding and rejects invalid argument shapes', () => {
  assert.equal(typeof native.processZeroRttDatagram, 'function');
  assert.equal(typeof native.processZeroRttDatagramInPlace, 'function');
  assert.equal(typeof native.generateMlKem512Keypair, 'function');
  assert.equal(typeof native.encapsulateMlKem512, 'function');
  assert.equal(typeof native.decapsulateMlKem512, 'function');
  assert.equal(typeof native.deriveZeroRttKey, 'function');
  assert.equal(typeof native.sealZeroRttPayload, 'function');
  assert.equal(typeof native.aeadLock, 'function');
  assert.equal(typeof native.aeadUnlock, 'function');
  assert.equal(typeof native.aeadUnlockInPlace, 'function');
  assert.equal(typeof native.resetReplayWindow, 'function');
  assert.equal(typeof native.allocateSecret, 'function');
  assert.equal(typeof native.destroySecret, 'function');
  assert.throws(() => native.allocateSecret(), /Expected one secret Buffer/);
  assert.throws(() => native.allocateSecret({}), /must be a Node.js Buffer/);
  assert.throws(() => native.allocateSecret(Buffer.alloc(0)), /must not be empty/);
  assert.throws(
    () => native.encapsulateMlKem512(Buffer.alloc(800), 'secure'),
    /boolean or \{ secureHandle: boolean \}/i,
  );
  assert.throws(
    () => native.decapsulateMlKem512(Buffer.alloc(768), Buffer.alloc(1632, 1), {
      secureHandle: 'yes',
    }),
    /must be a boolean/i,
  );
  assert.throws(
    () => native.decapsulateMlKem512(Buffer.alloc(767), Buffer.alloc(1632)),
    /exactly 768 bytes/i,
  );
  assert.throws(
    () => native.deriveZeroRttKey(Buffer.alloc(32), Buffer.alloc(4)),
    /exactly 812 bytes/i,
  );
  assert.throws(
    () => native.deriveZeroRttKey(Buffer.alloc(31), Buffer.alloc(812)),
    /exactly 32 bytes/i,
  );
  assert.throws(
    () => native.sealZeroRttPayload(Buffer.alloc(32), Buffer.alloc(812), Buffer.alloc(1)),
    /Invalid Zero-RTT header/i,
  );
  assert.throws(
    () => native.decapsulateMlKem512(Buffer.alloc(768), Buffer.alloc(1631)),
    /exactly 1632 bytes/i,
  );
  assert.throws(
    () => native.generateMlKem512Keypair('secure'),
    /boolean or \{ secureHandle: boolean \}/i,
  );
  assert.throws(
    () => native.generateMlKem512Keypair({ secureHandle: 'yes' }),
    /must be a boolean/i,
  );
  assert.throws(
    () => native.generateMlKem512Keypair(true, false),
    /Expected an optional boolean/i,
  );
  assert.throws(() => native.processZeroRttDatagram(), /Expected a frame Buffer/);
  assert.throws(
    () => native.processZeroRttDatagram(
      Buffer.alloc(0),
      Buffer.alloc(1632),
      1n,
      native.createReplayWindow(),
    ),
    /Invalid lattice wire frame/,
  );
  assert.throws(
    () => native.processZeroRttDatagram(
      Buffer.alloc(0),
      Buffer.alloc(1632),
      1,
      native.createReplayWindow(),
    ),
    /BigInt/,
  );
  assert.throws(
    () => native.processZeroRttDatagram(
      Buffer.alloc(0),
      {},
      1n,
      native.createReplayWindow(),
    ),
    /secure secret handle/i,
  );
  assert.throws(() => native.resetReplayWindow({}), /createReplayWindow/);
});

test('exposes correctly sized ML-KEM keypair and encapsulation fixtures', () => {
  const { publicKey, secretKey } = native.generateMlKem512Keypair();
  assert.equal(publicKey.length, 800);
  assert.equal(secretKey.length, 1632);

  const { ciphertext, sharedSecret } = native.encapsulateMlKem512(publicKey);
  assert.equal(ciphertext.length, 768);
  assert.equal(sharedSecret.length, 32);
  assert.throws(
    () => native.encapsulateMlKem512(Buffer.alloc(799)),
    /exactly 800 bytes/i,
  );
  secretKey.fill(0);
  sharedSecret.fill(0);
});

test('deriveZeroRttKey matches the key used by the Zero-RTT opener', () => {
  const { publicKey, secretKey } = native.generateMlKem512Keypair();
  const { ciphertext, sharedSecret } = native.encapsulateMlKem512(publicKey);
  const header = createHeaderAad({
    ciphertext,
    sequenceNumber: 89n,
    plaintextLength: 0,
  });
  const derivedKey = native.deriveZeroRttKey(sharedSecret, header);
  const kdfInput = Buffer.concat([
    Buffer.from('ZeroLabz-LatticeWire-v1', 'ascii'),
    sharedSecret,
    header.subarray(16, 24),
    header.subarray(4, 8),
    header.subarray(800, 812),
  ]);
  const expectedKey = createHashShake256(kdfInput);

  assert.deepEqual(derivedKey, expectedKey);
  derivedKey.fill(0);
  expectedKey.fill(0);
  kdfInput.fill(0);
  sharedSecret.fill(0);
  secretKey.fill(0);
});

test('derives and seals Zero-RTT payloads from secure shared-secret handles', (t) => {
  let serverPublicKey;
  let serverSecretKey;
  let clientSharedSecret;
  let derivedKeyHandle;
  try {
    ({
      publicKey: serverPublicKey,
      secretKey: serverSecretKey,
    } = native.generateMlKem512Keypair({
      secureHandle: true,
    }));
    let encapsulation;
    try {
      encapsulation = native.encapsulateMlKem512(
        serverPublicKey,
        { secureHandle: true },
      );
    } catch (error) {
      native.destroySecret(serverSecretKey);
      if (/secure memory|memory-lock limits|core dumps/i.test(error.message)) {
        t.skip(`The operating system did not permit secure memory allocation: ${error.message}`);
        return;
      }
      throw error;
    }

    clientSharedSecret = encapsulation.sharedSecret;
    const header = createHeaderAad({
      ciphertext: encapsulation.ciphertext,
      sequenceNumber: 90n,
      plaintextLength: Buffer.byteLength('secure shared-secret sealing'),
    });

    derivedKeyHandle = native.deriveZeroRttKey(
      clientSharedSecret,
      header,
      { secureHandle: true },
    );
    assert.equal(Buffer.isBuffer(derivedKeyHandle), false);
    assert.throws(
      () => native.deriveZeroRttKey(serverSecretKey, header),
      /exactly 32 bytes/i,
    );

    const plaintext = Buffer.from('secure shared-secret sealing');
    const datagram = native.sealZeroRttPayload(
      clientSharedSecret,
      header,
      plaintext,
    );
    assert.equal(datagram.length, 828 + plaintext.length);
    const opened = native.processZeroRttDatagram(
      datagram,
      serverSecretKey,
      0x0102030405060708n,
      native.createReplayWindow(),
    );
    assert.deepEqual(opened.plaintext, plaintext);

    native.destroySecret(derivedKeyHandle);
    derivedKeyHandle = null;
    native.destroySecret(clientSharedSecret);
    assert.throws(
      () => native.sealZeroRttPayload(
        clientSharedSecret,
        header,
        Buffer.from('after destruction'),
      ),
      /already been destroyed/i,
    );
    clientSharedSecret = null;
  } catch (error) {
    if (/secure memory|memory-lock limits|core dumps/i.test(error.message)) {
      t.skip(`The operating system did not permit secure memory allocation: ${error.message}`);
      return;
    }
    throw error;
  } finally {
    if (derivedKeyHandle !== null) {
      native.destroySecret(derivedKeyHandle);
    }
    if (clientSharedSecret !== null) {
      native.destroySecret(clientSharedSecret);
    }
    if (serverSecretKey !== undefined) {
      native.destroySecret(serverSecretKey);
    }
  }
});

test('standalone AEAD APIs consume secure keys and preserve wire-compatible ciphertext', (t) => {
  let secretKey;
  let sharedSecret;
  let derivedKey;
  try {
    const keypair = native.generateMlKem512Keypair({ secureHandle: true });
    secretKey = keypair.secretKey;
    const encapsulation = native.encapsulateMlKem512(
      keypair.publicKey,
      { secureHandle: true },
    );
    sharedSecret = encapsulation.sharedSecret;
    const header = createHeaderAad({
      ciphertext: encapsulation.ciphertext,
      sequenceNumber: 91n,
      plaintextLength: 0,
    });
    derivedKey = native.deriveZeroRttKey(
      sharedSecret,
      header,
      { secureHandle: true },
    );

    const nonce = header.subarray(800, 812);
    const aad = Buffer.from([0x01, 0x00, 0x00, 0x02]);
    const plaintext = Buffer.from('standalone AEAD with secure key');
    const sealed = native.aeadLock(derivedKey, nonce, plaintext, aad);
    assert.equal(sealed.length, plaintext.length + 16);
    assert.deepEqual(native.aeadUnlock(derivedKey, nonce, sealed, aad), plaintext);

    const inPlace = Buffer.from(sealed);
    const openedInPlace = native.aeadUnlockInPlace(
      derivedKey,
      nonce,
      inPlace,
      aad,
    );
    assert.equal(openedInPlace.buffer, inPlace);
    assert.equal(openedInPlace.plaintextLength, plaintext.length);
    assert.deepEqual(
      inPlace.subarray(0, openedInPlace.plaintextLength),
      plaintext,
    );
    assert.ok(inPlace.subarray(openedInPlace.plaintextLength).every((byte) => byte === 0));

    const zeroRttPacket = native.sealZeroRttPayload(
      sharedSecret,
      createHeaderAad({
        ciphertext: encapsulation.ciphertext,
        sequenceNumber: 92n,
        plaintextLength: plaintext.length,
      }),
      plaintext,
    );
    const zeroRttAad = zeroRttPacket.subarray(0, 812);
    const zeroRttKey = native.deriveZeroRttKey(
      sharedSecret,
      zeroRttAad,
      { secureHandle: true },
    );
    try {
      const crossOpened = native.aeadUnlock(
        zeroRttKey,
        zeroRttAad.subarray(800, 812),
        zeroRttPacket.subarray(812),
        zeroRttAad,
      );
      assert.deepEqual(crossOpened, plaintext);
    } finally {
      native.destroySecret(zeroRttKey);
    }

    assert.deepEqual(
      native.aeadUnlock(
        derivedKey,
        nonce,
        native.aeadLock(derivedKey, nonce, plaintext, Buffer.alloc(0)),
        null,
      ),
      plaintext,
    );
    assert.deepEqual(
      native.aeadUnlock(
        derivedKey,
        nonce,
        native.aeadLock(derivedKey, nonce, plaintext),
        undefined,
      ),
      plaintext,
    );

    const tampered = Buffer.from(sealed);
    tampered[tampered.length - 1] ^= 0x80;
    assert.throws(
      () => native.aeadUnlock(derivedKey, nonce, tampered, aad),
      /authentication failed/i,
    );
    const inPlaceTampered = Buffer.from(tampered);
    const before = Buffer.from(inPlaceTampered);
    assert.throws(
      () => native.aeadUnlockInPlace(
        derivedKey,
        nonce,
        inPlaceTampered,
        aad,
      ),
      /authentication failed/i,
    );
    assert.deepEqual(inPlaceTampered, before);

    assert.throws(
      () => native.aeadLock(secretKey, nonce, plaintext, aad),
      /exactly 32 bytes/i,
    );
  } catch (error) {
    if (/secure memory|memory-lock limits|core dumps/i.test(error.message)) {
      t.skip(`The operating system did not permit secure memory allocation: ${error.message}`);
      return;
    }
    throw error;
  } finally {
    if (derivedKey !== undefined) native.destroySecret(derivedKey);
    if (sharedSecret !== undefined) native.destroySecret(sharedSecret);
    if (secretKey !== undefined) native.destroySecret(secretKey);
  }
});

test('allows an explicitly owned replay window to be reset', () => {
  assert.equal(native.resetReplayWindow(native.createReplayWindow()), undefined);
});
