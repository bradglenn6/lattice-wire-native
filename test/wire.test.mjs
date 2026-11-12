import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';

const require = createRequire(import.meta.url);
const native = require('../build/Release/lattice_wire_native.node');

function createFrame({
  flags = 0,
  streamId = 42,
  sequenceNumber = 0x1020304050607080n,
  destinationKeyId = 0xCAFEBABE12345678n,
  payloadLength = 8,
} = {}) {
  const frame = Buffer.alloc(828 + payloadLength);
  frame.writeUInt16BE(0x5A4C, 0);
  frame.writeUInt8(1, 2);
  frame.writeUInt8(flags, 3);
  frame.writeUInt32BE(streamId, 4);
  frame.writeBigUInt64BE(sequenceNumber, 8);
  frame.writeBigUInt64BE(destinationKeyId, 16);
  frame.writeUInt16BE(payloadLength, 24);
  frame.writeUInt16BE(32, 26);
  return frame;
}

test('accepts a correctly sized frame and preserves 64-bit metadata', () => {
  const frame = createFrame();
  const result = native.processPacket(frame);
  assert.deepEqual(result, {
    streamId: 42,
    sequenceNumber: 0x1020304050607080n,
    destinationKeyId: 0xCAFEBABE12345678n,
    payloadLength: 8,
    ciphertextOffset: 32,
    nonceOffset: 800,
    payloadOffset: 812,
    tagOffset: 820,
    status: 'FRAME_VALID_UNAUTHENTICATED',
  });
});

test('accepts the maximum 1472-byte frame', () => {
  const result = native.processPacket(createFrame({ payloadLength: 644 }));
  assert.equal(result.payloadLength, 644);
  assert.equal(result.tagOffset + 16, 1472);
});

test('exposes bounded payload and tag slices, including an empty payload', () => {
  const frame = createFrame({ payloadLength: 0 });
  frame.fill(0xA5, 800, 812);
  frame.fill(0x5A, 812, 828);

  const result = native.processPacket(frame);
  assert.deepEqual(frame.subarray(result.payloadOffset, result.tagOffset), Buffer.alloc(0));
  assert.deepEqual(frame.subarray(result.tagOffset), Buffer.alloc(16, 0x5A));
  assert.equal(result.tagOffset + 16, frame.length);
});

test('rejects non-byte-array arguments and accepts Uint8Array views', () => {
  assert.throws(() => native.processPacket({}), TypeError);
  assert.throws(() => native.processPacket(new Uint16Array(414)), TypeError);

  const buffer = createFrame();
  const bytes = new Uint8Array(buffer);
  assert.equal(native.processPacket(bytes).status,
               'FRAME_VALID_UNAUTHENTICATED');
});

test('rejects a short frame', () => {
  assert.throws(() => native.processPacket(Buffer.alloc(827)), RangeError);
});

test('rejects bad magic', () => {
  const frame = createFrame();
  frame[0] = 0;
  assert.throws(() => native.processPacket(frame), /magic/i);
});

test('rejects unsupported versions and datagrams over the maximum size', () => {
  const unsupportedVersion = createFrame();
  unsupportedVersion[2] = 2;
  assert.throws(() => native.processPacket(unsupportedVersion), /version/i);

  assert.throws(
    () => native.processPacket(createFrame({ payloadLength: 645 })),
    /maximum frame size/i,
  );
});

test('rejects reserved flags and nonzero reserved header bytes', () => {
  const reservedFlag = createFrame();
  reservedFlag[3] = 0x04;
  assert.throws(() => native.processPacket(reservedFlag), /reserved flag/i);

  const reservedByte = createFrame();
  reservedByte[31] = 1;
  assert.throws(() => native.processPacket(reservedByte), /reserved header/i);
});

test('rejects an incorrect declared-length or actual-length value', () => {
  const wrongHeaderLength = createFrame();
  wrongHeaderLength.writeUInt16BE(28, 26);
  assert.throws(() => native.processPacket(wrongHeaderLength), /header length/i);

  const mismatchedPayload = createFrame();
  mismatchedPayload.writeUInt16BE(9, 24);
  assert.throws(() => native.processPacket(mismatchedPayload), /length/i);

  assert.throws(
    () => native.processPacket(Buffer.concat([createFrame(), Buffer.from([0])])),
    /length/i,
  );
});

test('requires ACK_ONLY payloads to be exactly eight bytes', () => {
  assert.equal(
    native.processPacket(createFrame({ flags: 1, payloadLength: 8 })).payloadLength,
    8,
  );
  const invalidAck = createFrame({ flags: 1, payloadLength: 7 });
  assert.throws(() => native.processPacket(invalidAck), /ACK_ONLY/i);
});
