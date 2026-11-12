const MAX_EPOCH = 0xffffffff;

function isEpoch(value) {
  return Number.isInteger(value) && value >= 0 && value <= MAX_EPOCH;
}

export class EpochKeyManager {
  #addon;
  #windowFactory;
  #onRotationError;
  #current = null;
  #previous = null;
  #disposed = false;
  #timer = null;

  constructor(
    addon,
    {
      initialEpoch = 1,
      createReplayWindow = () => addon.createReplayWindow(),
      onRotationError = (error) => console.error('Epoch key rotation failed:', error),
    } = {},
  ) {
    if (
      !addon ||
      typeof addon.generateMlKem512Keypair !== 'function' ||
      typeof addon.destroySecret !== 'function'
    ) {
      throw new TypeError('EpochKeyManager requires a compatible lattice wire addon.');
    }
    if (!isEpoch(initialEpoch)) {
      throw new RangeError('initialEpoch must be a valid uint32 integer.');
    }
    if (typeof createReplayWindow !== 'function') {
      throw new TypeError('createReplayWindow must be a function.');
    }
    if (typeof onRotationError !== 'function') {
      throw new TypeError('onRotationError must be a function.');
    }

    this.#addon = addon;
    this.#windowFactory = createReplayWindow;
    this.#onRotationError = onRotationError;
    this.#current = this.#createSlot(initialEpoch);
  }

  getPublicAdvertisement() {
    this.#assertAlive();
    return {
      epoch: this.#current.epoch,
      publicKey: this.#current.publicKey,
    };
  }

  rotate(nextEpoch = (this.#current.epoch + 1) >>> 0) {
    this.#assertAlive();
    if (!isEpoch(nextEpoch)) {
      throw new RangeError('nextEpoch must be a valid uint32 integer.');
    }
    if (
      nextEpoch === this.#current.epoch ||
      (this.#previous !== null && nextEpoch === this.#previous.epoch)
    ) {
      throw new RangeError(`Epoch ${nextEpoch} is already in the rotation window.`);
    }
    if (this.#previous !== null && this.#previous.leaseCount !== 0) {
      throw new Error(
        `Cannot rotate while epoch ${this.#previous.epoch} has active leases.`,
      );
    }

    // Keep at most two locked key allocations, even during rotation.
    this.#retirePrevious();

    const next = this.#createSlot(nextEpoch);
    this.#previous = this.#current;
    this.#current = next;
    return this.getPublicAdvertisement();
  }

  expirePrevious() {
    this.#assertAlive();
    if (this.#previous === null) {
      return false;
    }
    if (this.#previous.leaseCount !== 0) {
      throw new Error(
        `Cannot expire epoch ${this.#previous.epoch} while it has active leases.`,
      );
    }
    this.#retirePrevious();
    return true;
  }

  resolveEpoch(epochId) {
    this.#assertAlive();
    if (!isEpoch(epochId)) {
      return null;
    }
    const slot = this.#findSlot(epochId);
    return slot === null ? null : this.#publicSlot(slot);
  }

  // Hold a lease across asynchronous work; releasing it permits later rotation.
  acquireEpoch(epochId) {
    this.#assertAlive();
    if (!isEpoch(epochId)) {
      return null;
    }
    const slot = this.#findSlot(epochId);
    if (slot === null) {
      return null;
    }

    slot.leaseCount += 1;
    let released = false;
    return {
      ...this.#publicSlot(slot),
      release: () => {
        if (released) {
          return;
        }
        released = true;
        slot.leaseCount -= 1;
        if (slot.leaseCount === 0 && (slot.retired || this.#disposed)) {
          this.#destroySlot(slot);
        }
      },
    };
  }

  startAutoRotation(intervalMs) {
    this.#assertAlive();
    if (!Number.isFinite(intervalMs) || intervalMs <= 0) {
      throw new RangeError('intervalMs must be a positive finite number.');
    }
    this.stopAutoRotation();
    this.#timer = setInterval(() => {
      try {
        this.rotate();
      } catch (error) {
        this.#onRotationError(error);
      }
    }, intervalMs);
    this.#timer.unref?.();
  }

  stopAutoRotation() {
    if (this.#timer !== null) {
      clearInterval(this.#timer);
      this.#timer = null;
    }
  }

  destroy() {
    if (this.#disposed) {
      return;
    }
    this.stopAutoRotation();
    this.#disposed = true;

    const slots = [this.#previous, this.#current];
    this.#previous = null;
    this.#current = null;
    for (const slot of slots) {
      if (slot !== null) {
        slot.retired = true;
      }
      if (slot !== null && slot.leaseCount === 0) {
        this.#destroySlot(slot);
      }
    }
  }

  [Symbol.dispose]() {
    this.destroy();
  }

  get isDisposed() {
    return this.#disposed;
  }

  #createSlot(epoch) {
    const { publicKey, secretKey } = this.#addon.generateMlKem512Keypair({
      secureHandle: true,
    });
    let replayWindow;
    try {
      replayWindow = this.#windowFactory(epoch);
    } catch (error) {
      this.#addon.destroySecret(secretKey);
      throw error;
    }
    return {
      epoch,
      publicKey,
      secretKey,
      replayWindow,
      createdAt: Date.now(),
      leaseCount: 0,
      retired: false,
    };
  }

  #retirePrevious() {
    if (this.#previous !== null) {
      this.#previous.retired = true;
      this.#destroySlot(this.#previous);
      this.#previous = null;
    }
  }

  #destroySlot(slot) {
    if (slot.secretKey !== null) {
      this.#addon.destroySecret(slot.secretKey);
      slot.secretKey = null;
    }
  }

  #findSlot(epoch) {
    if (this.#current?.epoch === epoch) {
      return this.#current;
    }
    if (this.#previous?.epoch === epoch) {
      return this.#previous;
    }
    return null;
  }

  #publicSlot(slot) {
    return {
      epoch: slot.epoch,
      publicKey: slot.publicKey,
      secretKey: slot.secretKey,
      replayWindow: slot.replayWindow,
      createdAt: slot.createdAt,
    };
  }

  #assertAlive() {
    if (this.#disposed) {
      throw new Error('EpochKeyManager has been destroyed.');
    }
  }
}
