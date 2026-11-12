import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import test from 'node:test';

const require = createRequire(import.meta.url);
const native = require('../build/Release/lattice_wire_native.node');

function sealFrame({ key, nonce, aadHeader, ciphertext = Buffer.alloc(768), plaintext }) {
  const frame = Buffer.alloc(828 + plaintext.length);
  aadHeader.copy(frame, 0);
  ciphertext.copy(frame, 32);
  nonce.copy(frame, 800);

  const cipher = createCipheriv('chacha20-poly1305', key, nonce, {
    authTagLength: 16,
  });
  cipher.setAAD(frame.subarray(0, 812), { plaintextLength: plaintext.length });
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  encrypted.copy(frame, 812);
  cipher.getAuthTag().copy(frame, 812 + plaintext.length);
  return frame;
}

function createHeader(payloadLength, sequenceNumber = 123n) {
  const header = Buffer.alloc(32);
  header.writeUInt16BE(0x5A4C, 0);
  header.writeUInt8(1, 2);
  header.writeUInt32BE(9, 4);
  header.writeBigUInt64BE(sequenceNumber, 8);
  header.writeBigUInt64BE(456n, 16);
  header.writeUInt16BE(payloadLength, 24);
  header.writeUInt16BE(32, 26);
  return header;
}

test('native Monocypher AEAD test vector suite', () => {
  const executable = join(
    'build',
    'Release',
    process.platform === 'win32' ? 'aead_test.exe' : 'aead_test',
  );
  const output = execFileSync(executable, { encoding: 'utf8' });
  assert.match(output, /RFC 8439 AEAD tests passed/);
});

test('authenticates using the exact header, KEM ciphertext, and nonce AAD', () => {
  const key = randomBytes(32);
  const nonce = randomBytes(12);
  const plaintext = Buffer.from('authenticated payload');
  const frame = sealFrame({
    key,
    nonce,
    aadHeader: createHeader(plaintext.length),
    plaintext,
  });
  const result = native.processAuthenticatedPacket(
    frame,
    key,
    native.createReplayWindow(),
  );

  assert.equal(result.status, 'FRAME_AUTHENTICATED');
  assert.equal(result.sequenceNumber, 123n);
  assert.equal(result.streamId, 9);
  assert.deepEqual(result.plaintext, plaintext);
  assert.notDeepEqual(frame.subarray(812, 812 + plaintext.length), plaintext);
});

test('rejects altered header, KEM ciphertext, payload, tag, or incorrect key', () => {
  const key = randomBytes(32);
  const nonce = randomBytes(12);
  const plaintext = Buffer.from('do not release before authentication');
  const frame = sealFrame({
    key,
    nonce,
    aadHeader: createHeader(plaintext.length),
    plaintext,
  });
  const replayWindow = native.createReplayWindow();

  for (const offset of [4, 32, 800, 812, frame.length - 1]) {
    const altered = Buffer.from(frame);
    altered[offset] ^= 1;
    assert.throws(
      () => native.processAuthenticatedPacket(altered, key, replayWindow),
      /authentication failed/i,
    );
  }
  assert.throws(
    () => native.processAuthenticatedPacket(frame, randomBytes(32), replayWindow),
    /authentication failed/i,
  );

  const inflatedSequenceFrame = sealFrame({
    key,
    nonce: randomBytes(12),
    aadHeader: createHeader(plaintext.length, 2000n),
    plaintext,
  });
  inflatedSequenceFrame[inflatedSequenceFrame.length - 1] ^= 1;
  assert.throws(
    () => native.processAuthenticatedPacket(
      inflatedSequenceFrame,
      key,
      replayWindow,
    ),
    /authentication failed/i,
  );

  const validFrame = sealFrame({
    key,
    nonce: randomBytes(12),
    aadHeader: createHeader(plaintext.length, 10n),
    plaintext,
  });
  assert.equal(
    native.processAuthenticatedPacket(validFrame, key, replayWindow).status,
    'FRAME_AUTHENTICATED',
  );
  assert.throws(
    () => native.processAuthenticatedPacket(validFrame, key, replayWindow),
    /replay window/i,
  );
});

test('authenticates zero-length payloads and checks key input', () => {
  const key = randomBytes(32);
  const frame = sealFrame({
    key,
    nonce: randomBytes(12),
    aadHeader: createHeader(0),
    plaintext: Buffer.alloc(0),
  });
  const result = native.processAuthenticatedPacket(
    frame,
    key,
    native.createReplayWindow(),
  );
  assert.equal(result.status, 'FRAME_AUTHENTICATED');
  assert.equal(result.plaintext.length, 0);

  assert.throws(
    () => native.processAuthenticatedPacket(
      frame,
      Buffer.alloc(31),
      native.createReplayWindow(),
    ),
    /32 bytes/i,
  );
  assert.throws(
    () => native.processAuthenticatedPacket(frame, key, {}),
    /replay window/i,
  );
});
