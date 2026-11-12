const MAX_SEQ = 0xffffffffffffffffn;
const NONCE_BYTES = 12;

export class SlidingReplayWindow {
  #highestSeq = -1n;
  #bitmap = 0n;

  inspect(seq) {
    if (typeof seq !== 'bigint' || seq < 0n || seq > MAX_SEQ) {
      return false;
    }
    if (this.#highestSeq === -1n || seq > this.#highestSeq) {
      return true;
    }
    const diff = this.#highestSeq - seq;
    if (diff >= 64n) {
      return false;
    }
    return (this.#bitmap & (1n << diff)) === 0n;
  }

  commit(seq) {
    if (!this.inspect(seq)) {
      return false;
    }
    if (this.#highestSeq === -1n) {
      this.#highestSeq = seq;
      this.#bitmap = 1n;
      return true;
    }
    if (seq > this.#highestSeq) {
      const shift = seq - this.#highestSeq;
      this.#bitmap =
        shift >= 64n
          ? 1n
          : ((this.#bitmap << shift) | 1n) & MAX_SEQ;
      this.#highestSeq = seq;
      return true;
    }
    this.#bitmap |= 1n << (this.#highestSeq - seq);
    return true;
  }

  reset() {
    this.#highestSeq = -1n;
    this.#bitmap = 0n;
  }
}

export class OneRttSession {
  #addon;
  #key;
  #ownsKey;
  #baseNonce;
  #txNonceScratch = null;
  #rxNonceScratch = null;
  #txSeq;
  #replayWindow;
  #nativeState = null;
  #disposed = false;
  #busy = false;

  constructor(addon, key, {
    baseNonce = Buffer.alloc(NONCE_BYTES),
    initialTxSeq = 0n,
    replayWindow,
    ownsKey = true,
  } = {}) {
    if (!addon || typeof addon.aeadLock !== 'function' ||
        typeof addon.aeadUnlock !== 'function' ||
        typeof addon.aeadUnlockInPlace !== 'function') {
      throw new TypeError('OneRttSession requires a compatible lattice wire addon.');
    }
    if (key === null || typeof key !== 'object' ||
        (Buffer.isBuffer(key) && key.byteLength !== 32)) {
      throw new TypeError('key must be a 32-byte secure handle or Buffer.');
    }
    if (!Buffer.isBuffer(baseNonce) || baseNonce.byteLength !== NONCE_BYTES) {
      throw new RangeError('baseNonce must be a 12-byte Buffer.');
    }
    if (typeof initialTxSeq !== 'bigint' ||
        initialTxSeq < 0n || initialTxSeq > MAX_SEQ) {
      throw new RangeError('initialTxSeq must be a valid uint64 BigInt.');
    }
    const hasNativeStateApi =
      typeof addon.createOneRttState === 'function' &&
      typeof addon.resetOneRttReplayWindow === 'function' &&
      typeof addon.sealOneRttFrame === 'function' &&
      typeof addon.openOneRttFrame === 'function' &&
      typeof addon.openOneRttFrameInPlace === 'function' &&
      typeof addon.destroyOneRttState === 'function';
    const useNativeState = replayWindow === undefined && hasNativeStateApi;
    const selectedReplayWindow =
      replayWindow === undefined
        ? (useNativeState ? null : new SlidingReplayWindow())
        : replayWindow;
    if (!useNativeState &&
        (!selectedReplayWindow ||
         typeof selectedReplayWindow.inspect !== 'function' ||
         typeof selectedReplayWindow.commit !== 'function')) {
      throw new TypeError('replayWindow must implement inspect(seq) and commit(seq).');
    }

    this.#addon = addon;
    this.#key = key;
    this.#ownsKey = Boolean(ownsKey);
    this.#baseNonce = Buffer.from(baseNonce);
    this.#txSeq = initialTxSeq;
    this.#replayWindow = selectedReplayWindow;
    if (useNativeState) {
      this.#nativeState = addon.createOneRttState(baseNonce, initialTxSeq);
    } else {
      this.#txNonceScratch = Buffer.alloc(NONCE_BYTES);
      this.#rxNonceScratch = Buffer.alloc(NONCE_BYTES);
    }
  }

  get nextTxSequence() {
    this.#assertAlive();
    return this.#txSeq;
  }

  get isDisposed() {
    return this.#disposed;
  }

  seal(plaintext, aad = null) {
    this.#beginOperation();
    if (this.#txSeq > MAX_SEQ) {
      this.#busy = false;
      throw new RangeError('ERR_NONCE_EXHAUSTED: 64-bit outbound sequence counter exhausted.');
    }

    const sequenceNumber = this.#txSeq;
    if (this.#nativeState !== null) {
      try {
        const result = this.#addon.sealOneRttFrame(
          this.#key,
          this.#nativeState,
          plaintext,
          aad,
        );
        this.#txSeq += 1n;
        return result;
      } finally {
        this.#busy = false;
      }
    }
    this.#txSeq += 1n;
    this.#writeNonce(this.#txNonceScratch, sequenceNumber);
    try {
      const sealed = this.#addon.aeadLock(
        this.#key,
        this.#txNonceScratch,
        plaintext,
        aad,
      );
      return { sequenceNumber, sealed };
    } finally {
      this.#txNonceScratch.fill(0);
      this.#busy = false;
    }
  }

  open(sequenceNumber, sealed, aad = null) {
    this.#beginOperation();
    if (this.#nativeState !== null) {
      try {
        return this.#addon.openOneRttFrame(
          this.#key,
          this.#nativeState,
          sequenceNumber,
          sealed,
          aad,
        );
      } finally {
        this.#busy = false;
      }
    }
    try {
      this.#validateSeq(sequenceNumber);
      if (this.#replayWindow.inspect(sequenceNumber) !== true) {
        throw this.#replayError(sequenceNumber);
      }

      this.#writeNonce(this.#rxNonceScratch, sequenceNumber);
      const plaintext = this.#addon.aeadUnlock(
        this.#key,
        this.#rxNonceScratch,
        sealed,
        aad,
      );
      try {
        if (this.#replayWindow.commit(sequenceNumber) !== true) {
          throw this.#replayError(sequenceNumber);
        }
      } catch (error) {
        if (Buffer.isBuffer(plaintext)) {
          plaintext.fill(0);
        }
        throw error;
      }
      return plaintext;
    } finally {
      this.#rxNonceScratch.fill(0);
      this.#busy = false;
    }
  }

  openInPlace(sequenceNumber, sealedBuffer, aad = null) {
    this.#beginOperation();
    if (this.#nativeState !== null) {
      try {
        return this.#addon.openOneRttFrameInPlace(
          this.#key,
          this.#nativeState,
          sequenceNumber,
          sealedBuffer,
          aad,
        );
      } finally {
        this.#busy = false;
      }
    }
    try {
      this.#validateSeq(sequenceNumber);
      if (this.#replayWindow.inspect(sequenceNumber) !== true) {
        throw this.#replayError(sequenceNumber);
      }

      this.#writeNonce(this.#rxNonceScratch, sequenceNumber);
      const result = this.#addon.aeadUnlockInPlace(
        this.#key,
        this.#rxNonceScratch,
        sealedBuffer,
        aad,
      );
      try {
        if (this.#replayWindow.commit(sequenceNumber) !== true) {
          throw this.#replayError(sequenceNumber);
        }
      } catch (error) {
        if (Buffer.isBuffer(result?.buffer)) {
          result.buffer.fill(0);
        }
        throw error;
      }
      return result;
    } finally {
      this.#rxNonceScratch.fill(0);
      this.#busy = false;
    }
  }

  destroy() {
    if (this.#disposed) {
      return;
    }
    if (this.#busy) {
      throw new Error('Cannot destroy OneRttSession during an active operation.');
    }
    this.#disposed = true;
    this.#baseNonce.fill(0);
    this.#txNonceScratch?.fill(0);
    this.#rxNonceScratch?.fill(0);

    const key = this.#key;
    this.#key = null;
    try {
      if (this.#ownsKey && key !== null) {
        if (Buffer.isBuffer(key)) {
          key.fill(0);
        } else {
          this.#addon.destroySecret(key);
        }
      }
    } finally {
      if (this.#nativeState !== null) {
        this.#addon.destroyOneRttState(this.#nativeState);
        this.#nativeState = null;
      }
    }
  }

  [Symbol.dispose]() {
    this.destroy();
  }

  #writeNonce(target, sequenceNumber) {
    this.#baseNonce.copy(target);
    const high = Number((sequenceNumber >> 32n) & 0xffffffffn);
    const low = Number(sequenceNumber & 0xffffffffn);
    target.writeUInt32BE((target.readUInt32BE(4) ^ high) >>> 0, 4);
    target.writeUInt32BE((target.readUInt32BE(8) ^ low) >>> 0, 8);
  }

  #validateSeq(sequenceNumber) {
    if (typeof sequenceNumber !== 'bigint' ||
        sequenceNumber < 0n || sequenceNumber > MAX_SEQ) {
      throw new RangeError('sequenceNumber must be a valid uint64 BigInt.');
    }
  }

  #replayError(sequenceNumber) {
    const error = new Error(`Replay or stale sequence number rejected: ${sequenceNumber}`);
    error.code = 'ERR_REPLAY_DETECTED';
    return error;
  }

  #beginOperation() {
    this.#assertAlive();
    if (this.#busy) {
      const error = new Error('OneRttSession operations cannot be re-entered.');
      error.code = 'ERR_SESSION_REENTRANT';
      throw error;
    }
    this.#busy = true;
  }

  #assertAlive() {
    if (this.#disposed) {
      const error = new Error('OneRttSession has been destroyed.');
      error.code = 'ERR_SESSION_DESTROYED';
      throw error;
    }
  }
}
