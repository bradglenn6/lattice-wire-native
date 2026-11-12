import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { bench, group, run } from 'mitata';
import {
  OneRttSession,
  SlidingReplayWindow,
} from '../lib/crypto/OneRttSession.js';

const require = createRequire(import.meta.url);
const native = require('../build/Release/lattice_wire_native.node');

const HEADER_SIZE = 32;
const KEM_CIPHERTEXT_SIZE = 768;
const NONCE_SIZE = 12;
const TAG_SIZE = 16;
const PAYLOAD_OFFSET = HEADER_SIZE + KEM_CIPHERTEXT_SIZE + NONCE_SIZE;
const FRAME_OVERHEAD = PAYLOAD_OFFSET + TAG_SIZE;
const MAX_PAYLOAD_SIZE = 644;
const TARGET_KEY_ID = 0xFEEDBEEF01020304n;
const STREAM_ID = 1;
const PAYLOAD = Buffer.from('bench-payload-data-32-bytes-pad!');
const BENCH_FRAMES_COUNT = 4096;

for (const name of [
  'generateMlKem512Keypair',
  'encapsulateMlKem512',
  'createReplayWindow',
  'resetReplayWindow',
  'processAuthenticatedPacket',
  'processZeroRttDatagram',
  'processZeroRttDatagramInPlace',
  'allocateSecret',
  'destroySecret',
  'deriveZeroRttKey',
  'sealZeroRttPayload',
  'aeadLock',
  'aeadUnlock',
  'aeadUnlockInPlace',
  'createOneRttState',
  'resetOneRttReplayWindow',
  'sealOneRttFrame',
  'openOneRttFrame',
  'openOneRttFrameInPlace',
  'destroyOneRttState',
]) {
  if (typeof native[name] !== 'function') {
    throw new TypeError(`Native addon must export ${name}()`);
  }
}

if (PAYLOAD.length > MAX_PAYLOAD_SIZE) {
  throw new RangeError(`payload exceeds the ${MAX_PAYLOAD_SIZE}-byte limit`);
}

const { publicKey, secretKey } = native.generateMlKem512Keypair();
if (publicKey.length !== 800 || secretKey.length !== 1632) {
  throw new Error('Native addon returned ML-KEM-512 keys with invalid lengths');
}
const { ciphertext: stagedCiphertext, sharedSecret: stagedSharedSecret } =
  native.encapsulateMlKem512(publicKey);

const decapsulationBenchmark = execFileSync(
  join(
    'build',
    'Release',
    process.platform === 'win32' ? 'mlkem512_bench.exe' : 'mlkem512_bench',
  ),
  { encoding: 'utf8' },
);

function createZeroRttDatagram({
  sequenceNumber,
  payload = PAYLOAD,
  corruptTag = false,
  retainAeadKey = false,
} = {}) {
  if (typeof sequenceNumber !== 'bigint' ||
      sequenceNumber < 0n ||
      sequenceNumber > 0xFFFFFFFFFFFFFFFFn) {
    throw new RangeError('sequenceNumber must be an unsigned 64-bit BigInt');
  }
  if (!Buffer.isBuffer(payload) || payload.length > MAX_PAYLOAD_SIZE) {
    throw new RangeError(`payload must be a Buffer of at most ${MAX_PAYLOAD_SIZE} bytes`);
  }

  const frame = Buffer.alloc(FRAME_OVERHEAD + payload.length);
  frame.writeUInt16BE(0x5A4C, 0);
  frame.writeUInt8(0x01, 2);
  frame.writeUInt8(0, 3);
  frame.writeUInt32BE(STREAM_ID, 4);
  frame.writeBigUInt64BE(sequenceNumber, 8);
  frame.writeBigUInt64BE(TARGET_KEY_ID, 16);
  frame.writeUInt16BE(payload.length, 24);
  frame.writeUInt16BE(HEADER_SIZE, 26);

  const { ciphertext, sharedSecret } = native.encapsulateMlKem512(publicKey);
  if (ciphertext.length !== KEM_CIPHERTEXT_SIZE || sharedSecret.length !== 32) {
    sharedSecret.fill(0);
    throw new Error('Native addon returned invalid ML-KEM-512 encapsulation sizes');
  }
  ciphertext.copy(frame, HEADER_SIZE);

  const nonce = crypto.randomBytes(NONCE_SIZE);
  nonce.copy(frame, HEADER_SIZE + KEM_CIPHERTEXT_SIZE);

  const kdfInput = Buffer.alloc(23 + sharedSecret.length + 8 + 4 + nonce.length);
  let offset = 0;
  offset += Buffer.from('ZeroLabz-LatticeWire-v1', 'ascii').copy(kdfInput, offset);
  offset += sharedSecret.copy(kdfInput, offset);
  kdfInput.writeBigUInt64BE(TARGET_KEY_ID, offset);
  offset += 8;
  kdfInput.writeUInt32BE(STREAM_ID, offset);
  offset += 4;
  offset += nonce.copy(kdfInput, offset);

  const aeadKey = crypto.createHash('shake256', { outputLength: 32 })
    .update(kdfInput)
    .digest();
  sharedSecret.fill(0);
  kdfInput.fill(0);

  const cipher = crypto.createCipheriv('chacha20-poly1305', aeadKey, nonce, {
    authTagLength: TAG_SIZE,
  });
  cipher.setAAD(frame.subarray(0, PAYLOAD_OFFSET), {
    plaintextLength: payload.length,
  });
  const encrypted = Buffer.concat([cipher.update(payload), cipher.final()]);
  encrypted.copy(frame, PAYLOAD_OFFSET);
  const tag = cipher.getAuthTag();
  if (corruptTag) {
    tag[0] ^= 1;
  }
  tag.copy(frame, PAYLOAD_OFFSET + payload.length);
  if (!retainAeadKey) {
    aeadKey.fill(0);
  }

  return { frame, aeadKey: retainAeadKey ? aeadKey : null };
}

const benchFrames = Array.from({ length: BENCH_FRAMES_COUNT }, (_, index) =>
  createZeroRttDatagram({ sequenceNumber: BigInt(index + 1) }).frame);
const sampleSymmetric = createZeroRttDatagram({
  sequenceNumber: 1_000_000n,
  retainAeadKey: true,
});
const sampleCorruptTag = createZeroRttDatagram({
  sequenceNumber: 2_000_000n,
  corruptTag: true,
}).frame;
const sampleReplayFrame = benchFrames[0];

const symmetricReplayWindow = native.createReplayWindow();
const fullReplayWindow = native.createReplayWindow();
const tamperedReplayWindow = native.createReplayWindow();
const replayWindow = native.createReplayWindow();
native.processZeroRttDatagram(
  sampleReplayFrame,
  secretKey,
  TARGET_KEY_ID,
  replayWindow,
);

function expectFailure(callback, expectedMessage) {
  try {
    callback();
  } catch (error) {
    if (expectedMessage.test(error.message)) {
      return;
    }
    throw error;
  }
  throw new Error(`Expected failure matching ${expectedMessage}`);
}

let frameIndex = 0;
let warmupSequence = 3_000_000n;
const warmupWindow = native.createReplayWindow();
for (let i = 0; i < 32; i++) {
  const { frame } = createZeroRttDatagram({ sequenceNumber: warmupSequence++ });
  native.processZeroRttDatagram(frame, secretKey, TARGET_KEY_ID, warmupWindow);
}

const handleHeader = Buffer.alloc(PAYLOAD_OFFSET);
handleHeader.writeUInt16BE(0x5A4C, 0);
handleHeader.writeUInt8(0x01, 2);
handleHeader.writeUInt8(0, 3);
handleHeader.writeUInt32BE(STREAM_ID, 4);
handleHeader.writeBigUInt64BE(4_000_000n, 8);
handleHeader.writeBigUInt64BE(TARGET_KEY_ID, 16);
handleHeader.writeUInt16BE(256, 24);
handleHeader.writeUInt16BE(HEADER_SIZE, 26);
stagedCiphertext.copy(handleHeader, HEADER_SIZE);
crypto.randomBytes(NONCE_SIZE).copy(
  handleHeader,
  HEADER_SIZE + KEM_CIPHERTEXT_SIZE,
);
const handlePayload = Buffer.alloc(256, 0x61);
const handleWirePacket = native.sealZeroRttPayload(
  stagedSharedSecret,
  handleHeader,
  handlePayload,
);
const handleScratchPacket = Buffer.allocUnsafe(handleWirePacket.byteLength);
const handleBufferReplayWindow = native.createReplayWindow();
const handleSecureReplayWindow = native.createReplayWindow();
let secretKeyHandle;
let sharedSecretHandle;
let aeadKeyBuffer;
let aeadKeyHandle;
let sessionBuf;
let sessionHandle;
let rxWindowBuf;
let rxWindowHandle;
let nonce1Rtt;
let aad1Rtt;
let sealed1Rtt;
let scratch1Rtt;
let sessionSealed0;
let sessionSequence0;
let nativeTxStateBuffer;
let nativeTxStateHandle;
let nativeRxStateBuffer;
let nativeRxStateHandle;
let nativeSealedBuffer;
let nativeSealedHandle;
let nativeSequenceBuffer;
let nativeSequenceHandle;
let nativeScratchBuffer;
let nativeScratchHandle;
try {
  secretKeyHandle = native.allocateSecret(secretKey);
  sharedSecretHandle = native.allocateSecret(stagedSharedSecret);
} catch (error) {
  if (secretKeyHandle !== undefined) {
    native.destroySecret(secretKeyHandle);
  }
  secretKey.fill(0);
  stagedSharedSecret.fill(0);
  throw error;
}

group('Zero-RTT Lattice Wire: receive-path microbenchmarks', () => {
  bench('AEAD-only pipeline [FrameView + ChaCha20-Poly1305]', () => {
    native.resetReplayWindow(symmetricReplayWindow);
    native.processAuthenticatedPacket(
      sampleSymmetric.frame,
      sampleSymmetric.aeadKey,
      symmetricReplayWindow,
    );
  });

  bench('Full pipeline [ML-KEM-512 + SHAKE256 + AEAD + replay commit]', () => {
    const frame = benchFrames[frameIndex];
    frameIndex = (frameIndex + 1) & (BENCH_FRAMES_COUNT - 1);
    native.resetReplayWindow(fullReplayWindow);
    native.processZeroRttDatagram(
      frame,
      secretKey,
      TARGET_KEY_ID,
      fullReplayWindow,
    );
  });

  bench('Tampered AEAD tag [authentication failure, no replay commit]', () => {
    native.resetReplayWindow(tamperedReplayWindow);
    expectFailure(
      () => native.processZeroRttDatagram(
        sampleCorruptTag,
        secretKey,
        TARGET_KEY_ID,
        tamperedReplayWindow,
      ),
      /authentication failed/i,
    );
  });

  bench('Replay filter rejection [read-only inspect]', () => {
    expectFailure(
      () => native.processZeroRttDatagram(
        sampleReplayFrame,
        secretKey,
        TARGET_KEY_ID,
        replayWindow,
      ),
      /replay window rejected/i,
    );
  });
});

group('Zero-RTT KDF: Buffer vs. Secure Handle', () => {
  bench('deriveZeroRttKey (Buffer sharedSecret)', () => {
    native.deriveZeroRttKey(stagedSharedSecret, handleHeader).fill(0);
  });

  bench('deriveZeroRttKey (Secure Handle sharedSecret)', () => {
    native.deriveZeroRttKey(sharedSecretHandle, handleHeader).fill(0);
  });
});

group('Zero-RTT Client Seal (256B payload): Buffer vs. Secure Handle', () => {
  bench('sealZeroRttPayload (Buffer sharedSecret)', () => {
    native.sealZeroRttPayload(stagedSharedSecret, handleHeader, handlePayload);
  });

  bench('sealZeroRttPayload (Secure Handle sharedSecret)', () => {
    native.sealZeroRttPayload(sharedSecretHandle, handleHeader, handlePayload);
  });
});

group('Zero-RTT Server Open (Allocating): Buffer vs. Secure Handle', () => {
  bench('processZeroRttDatagram (Buffer secretKey)', () => {
    native.resetReplayWindow(handleBufferReplayWindow);
    native.processZeroRttDatagram(
      handleWirePacket,
      secretKey,
      TARGET_KEY_ID,
      handleBufferReplayWindow,
    );
  });

  bench('processZeroRttDatagram (Secure Handle secretKey)', () => {
    native.resetReplayWindow(handleSecureReplayWindow);
    native.processZeroRttDatagram(
      handleWirePacket,
      secretKeyHandle,
      TARGET_KEY_ID,
      handleSecureReplayWindow,
    );
  });
});

group('Zero-RTT Server Open (In-Place): Buffer vs. Secure Handle', () => {
  bench('processZeroRttDatagramInPlace (Buffer secretKey)', () => {
    handleWirePacket.copy(handleScratchPacket);
    native.resetReplayWindow(handleBufferReplayWindow);
    native.processZeroRttDatagramInPlace(
      handleScratchPacket,
      secretKey,
      TARGET_KEY_ID,
      handleBufferReplayWindow,
    );
  });

  bench('processZeroRttDatagramInPlace (Secure Handle secretKey)', () => {
    handleWirePacket.copy(handleScratchPacket);
    native.resetReplayWindow(handleSecureReplayWindow);
    native.processZeroRttDatagramInPlace(
      handleScratchPacket,
      secretKeyHandle,
      TARGET_KEY_ID,
      handleSecureReplayWindow,
    );
  });
});

group('1-RTT Standalone aeadLock (256B payload): Buffer vs. Secure Handle', () => {
  bench('aeadLock (Buffer key)', () => {
    native.aeadLock(aeadKeyBuffer, nonce1Rtt, handlePayload, aad1Rtt);
  });

  bench('aeadLock (Secure Handle key)', () => {
    native.aeadLock(aeadKeyHandle, nonce1Rtt, handlePayload, aad1Rtt);
  });
});

group('1-RTT Standalone aeadUnlock (Allocating): Buffer vs. Secure Handle', () => {
  bench('aeadUnlock (Buffer key)', () => {
    native.aeadUnlock(aeadKeyBuffer, nonce1Rtt, sealed1Rtt, aad1Rtt);
  });

  bench('aeadUnlock (Secure Handle key)', () => {
    native.aeadUnlock(aeadKeyHandle, nonce1Rtt, sealed1Rtt, aad1Rtt);
  });
});

group('1-RTT Standalone aeadUnlockInPlace: Buffer vs. Secure Handle', () => {
  bench('aeadUnlockInPlace (Buffer key)', () => {
    sealed1Rtt.copy(scratch1Rtt);
    native.aeadUnlockInPlace(aeadKeyBuffer, nonce1Rtt, scratch1Rtt, aad1Rtt);
  });

  bench('aeadUnlockInPlace (Secure Handle key)', () => {
    sealed1Rtt.copy(scratch1Rtt);
    native.aeadUnlockInPlace(aeadKeyHandle, nonce1Rtt, scratch1Rtt, aad1Rtt);
  });
});

group('1-RTT OneRttSession.seal (256B payload): Buffer vs. Secure Handle', () => {
  bench('OneRttSession.seal (Buffer key)', () => {
    sessionBuf.seal(handlePayload, aad1Rtt);
  });

  bench('OneRttSession.seal (Secure Handle key)', () => {
    sessionHandle.seal(handlePayload, aad1Rtt);
  });
});

group('1-RTT OneRttSession.open (Allocating): Buffer vs. Secure Handle', () => {
  bench('OneRttSession.open (Buffer key)', () => {
    rxWindowBuf.reset();
    sessionBuf.open(sessionSequence0, sessionSealed0, aad1Rtt);
  });

  bench('OneRttSession.open (Secure Handle key)', () => {
    rxWindowHandle.reset();
    sessionHandle.open(sessionSequence0, sessionSealed0, aad1Rtt);
  });
});

group('1-RTT OneRttSession.openInPlace: Buffer vs. Secure Handle', () => {
  bench('OneRttSession.openInPlace (Buffer key)', () => {
    rxWindowBuf.reset();
    sessionSealed0.copy(scratch1Rtt);
    sessionBuf.openInPlace(sessionSequence0, scratch1Rtt, aad1Rtt);
  });

  bench('OneRttSession.openInPlace (Secure Handle key)', () => {
    rxWindowHandle.reset();
    sessionSealed0.copy(scratch1Rtt);
    sessionHandle.openInPlace(sessionSequence0, scratch1Rtt, aad1Rtt);
  });
});

group('1-RTT Native sealOneRttFrame: Buffer vs. Secure Handle', () => {
  bench('sealOneRttFrame (Buffer key)', () => {
    native.sealOneRttFrame(
      aeadKeyBuffer,
      nativeTxStateBuffer,
      handlePayload,
      aad1Rtt,
    );
  });

  bench('sealOneRttFrame (Secure Handle key)', () => {
    native.sealOneRttFrame(
      aeadKeyHandle,
      nativeTxStateHandle,
      handlePayload,
      aad1Rtt,
    );
  });
});

group('1-RTT Native openOneRttFrame: Buffer vs. Secure Handle', () => {
  bench('openOneRttFrame (Buffer key)', () => {
    native.resetOneRttReplayWindow(nativeRxStateBuffer);
    native.openOneRttFrame(
      aeadKeyBuffer,
      nativeRxStateBuffer,
      nativeSequenceBuffer,
      nativeSealedBuffer,
      aad1Rtt,
    );
  });

  bench('openOneRttFrame (Secure Handle key)', () => {
    native.resetOneRttReplayWindow(nativeRxStateHandle);
    native.openOneRttFrame(
      aeadKeyHandle,
      nativeRxStateHandle,
      nativeSequenceHandle,
      nativeSealedHandle,
      aad1Rtt,
    );
  });
});

group('1-RTT Native openOneRttFrameInPlace: Buffer vs. Secure Handle', () => {
  bench('openOneRttFrameInPlace (Buffer key)', () => {
    native.resetOneRttReplayWindow(nativeRxStateBuffer);
    nativeSealedBuffer.copy(nativeScratchBuffer);
    native.openOneRttFrameInPlace(
      aeadKeyBuffer,
      nativeRxStateBuffer,
      nativeSequenceBuffer,
      nativeScratchBuffer,
      aad1Rtt,
    );
  });

  bench('openOneRttFrameInPlace (Secure Handle key)', () => {
    native.resetOneRttReplayWindow(nativeRxStateHandle);
    nativeSealedHandle.copy(nativeScratchHandle);
    native.openOneRttFrameInPlace(
      aeadKeyHandle,
      nativeRxStateHandle,
      nativeSequenceHandle,
      nativeScratchHandle,
      aad1Rtt,
    );
  });
});

console.log('\n=============================================================');
console.log(' ZeroLabz Lattice Wire: End-to-End Receive Pipeline          ');
console.log(' Protocol: SPEC-LATTICE-WIRE-01                              ');
console.log(' Cryptography: ML-KEM-512 + SHAKE256 + ChaCha20-Poly1305     ');
console.log(` Frame size: ${FRAME_OVERHEAD + PAYLOAD.length}B | AAD: ${PAYLOAD_OFFSET}B | Payload: ${PAYLOAD.length}B`);
console.log(' Replay windows are reset for repeatable accepted-path timing.');
console.log(' Buffer/secure-handle comparisons include the same KEM/AEAD work; they do not isolate Node-API lookup cost.');
console.log('=============================================================\n');
console.log(`Direct native baseline: ${decapsulationBenchmark.trim()}\n`);

try {
  aeadKeyBuffer = native.deriveZeroRttKey(stagedSharedSecret, handleHeader);
  aeadKeyHandle = native.deriveZeroRttKey(
    sharedSecretHandle,
    handleHeader,
    { secureHandle: true },
  );
  nonce1Rtt = Buffer.from(
    handleHeader.subarray(HEADER_SIZE + KEM_CIPHERTEXT_SIZE, PAYLOAD_OFFSET),
  );
  aad1Rtt = Buffer.from([0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01]);
  sealed1Rtt = native.aeadLock(
    aeadKeyBuffer,
    nonce1Rtt,
    handlePayload,
    aad1Rtt,
  );
  scratch1Rtt = Buffer.allocUnsafe(sealed1Rtt.byteLength);

  rxWindowBuf = new SlidingReplayWindow();
  rxWindowHandle = new SlidingReplayWindow();
  // Inject JS windows so benchmark iterations can reset replay state without timing resets.
  sessionBuf = new OneRttSession(native, aeadKeyBuffer, {
    baseNonce: nonce1Rtt,
    replayWindow: rxWindowBuf,
    ownsKey: false,
  });
  sessionHandle = new OneRttSession(native, aeadKeyHandle, {
    baseNonce: nonce1Rtt,
    replayWindow: rxWindowHandle,
    // Both representations contain the same key; keep benchmark transmit nonce spaces disjoint.
    initialTxSeq: 0x8000000000000000n,
    ownsKey: false,
  });
  ({
    sequenceNumber: sessionSequence0,
    sealed: sessionSealed0,
  } = sessionBuf.seal(handlePayload, aad1Rtt));

    nativeTxStateBuffer = native.createOneRttState(nonce1Rtt);
    nativeTxStateHandle = native.createOneRttState(
      nonce1Rtt,
      0x8000000000000000n,
    );
    nativeRxStateBuffer = native.createOneRttState(nonce1Rtt);
    nativeRxStateHandle = native.createOneRttState(nonce1Rtt);
    ({
      sequenceNumber: nativeSequenceBuffer,
      sealed: nativeSealedBuffer,
    } = native.sealOneRttFrame(
      aeadKeyBuffer,
      nativeTxStateBuffer,
      handlePayload,
      aad1Rtt,
    ));
    ({
      sequenceNumber: nativeSequenceHandle,
      sealed: nativeSealedHandle,
    } = native.sealOneRttFrame(
      aeadKeyHandle,
      nativeTxStateHandle,
      handlePayload,
      aad1Rtt,
    ));
    nativeScratchBuffer = Buffer.allocUnsafe(nativeSealedBuffer.byteLength);
    nativeScratchHandle = Buffer.allocUnsafe(nativeSealedHandle.byteLength);

  await run({
    percentiles: true,
    silent: false,
  });
} finally {
  sessionBuf?.destroy();
  sessionHandle?.destroy();
  for (const state of [
    nativeTxStateBuffer,
    nativeTxStateHandle,
    nativeRxStateBuffer,
    nativeRxStateHandle,
  ]) {
    if (state !== undefined) {
      native.destroyOneRttState(state);
    }
  }
  if (aeadKeyHandle !== undefined) {
    native.destroySecret(aeadKeyHandle);
  }
  aeadKeyBuffer?.fill(0);
  sampleSymmetric.aeadKey.fill(0);
  native.destroySecret(secretKeyHandle);
  native.destroySecret(sharedSecretHandle);
  secretKey.fill(0);
  stagedSharedSecret.fill(0);
}
