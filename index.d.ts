/// <reference types="node" />

declare const SecureSecretBrand: unique symbol;
declare const OneRttStateBrand: unique symbol;
declare const ReplayWindowBrand: unique symbol;

export interface SecureSecretHandle {
  readonly [SecureSecretBrand]: true;
}

export interface OneRttStateHandle {
  readonly [OneRttStateBrand]: true;
}

export interface ReplayWindowHandle {
  readonly [ReplayWindowBrand]: true;
}

export type SecretInput = Buffer | SecureSecretHandle;
export type SecureHandleOption = true | { secureHandle: true };
export type BufferOption = false | { secureHandle?: false };
export type SecureHandleOptions = SecureHandleOption | BufferOption;

export interface MlKem512BufferKeypair {
  publicKey: Buffer;
  secretKey: Buffer;
}

export interface MlKem512SecureKeypair {
  publicKey: Buffer;
  secretKey: SecureSecretHandle;
}

export interface MlKem512BufferEncapsulation {
  ciphertext: Buffer;
  sharedSecret: Buffer;
}

export interface MlKem512SecureEncapsulation {
  ciphertext: Buffer;
  sharedSecret: SecureSecretHandle;
}

export interface InPlacePlaintextResult {
  buffer: Buffer;
  plaintextLength: number;
}

export interface OneRttSealResult {
  sequenceNumber: bigint;
  sealed: Buffer;
}

export interface ParsedFrame {
  streamId: number;
  sequenceNumber: bigint;
  destinationKeyId: bigint;
  payloadLength: number;
  ciphertextOffset: number;
  nonceOffset: number;
  payloadOffset: number;
  tagOffset: number;
  status: 'FRAME_VALID_UNAUTHENTICATED';
}

export interface AuthenticatedFrame {
  status: 'FRAME_AUTHENTICATED';
  streamId: number;
  sequenceNumber: bigint;
  plaintext: Buffer;
}

export interface InPlaceZeroRttResult {
  frame: Buffer;
  plaintextOffset: number;
  plaintextLength: number;
  sequenceNumber: bigint;
  streamId: number;
  status: 'FRAME_AUTHENTICATED';
}

export function allocateSecret(source: Buffer): SecureSecretHandle;
export function destroySecret(handle: SecureSecretHandle): void;

export function generateMlKem512Keypair(
  options: SecureHandleOption,
): MlKem512SecureKeypair;
export function generateMlKem512Keypair(
  options?: BufferOption,
): MlKem512BufferKeypair;
export function generateMlKem512Keypair(
  options?: SecureHandleOptions,
): MlKem512BufferKeypair | MlKem512SecureKeypair;

export function encapsulateMlKem512(
  publicKey: Buffer,
  options: SecureHandleOption,
): MlKem512SecureEncapsulation;
export function encapsulateMlKem512(
  publicKey: Buffer,
  options?: BufferOption,
): MlKem512BufferEncapsulation;
export function encapsulateMlKem512(
  publicKey: Buffer,
  options?: SecureHandleOptions,
): MlKem512BufferEncapsulation | MlKem512SecureEncapsulation;

export function decapsulateMlKem512(
  ciphertext: Buffer,
  secretKey: SecretInput,
  options: SecureHandleOption,
): SecureSecretHandle;
export function decapsulateMlKem512(
  ciphertext: Buffer,
  secretKey: SecretInput,
  options?: BufferOption,
): Buffer;
export function decapsulateMlKem512(
  ciphertext: Buffer,
  secretKey: SecretInput,
  options?: SecureHandleOptions,
): Buffer | SecureSecretHandle;

export function deriveZeroRttKey(
  sharedSecret: SecretInput,
  headerAad: Buffer,
  options: SecureHandleOption,
): SecureSecretHandle;
export function deriveZeroRttKey(
  sharedSecret: SecretInput,
  headerAad: Buffer,
  options?: BufferOption,
): Buffer;
export function deriveZeroRttKey(
  sharedSecret: SecretInput,
  headerAad: Buffer,
  options?: SecureHandleOptions,
): Buffer | SecureSecretHandle;

export function sealZeroRttPayload(
  sharedSecret: SecretInput,
  headerAad: Buffer,
  plaintext: Buffer,
): Buffer;
export function processPacket(frame: Buffer | Uint8Array): ParsedFrame;
export function processAuthenticatedPacket(
  frame: Buffer,
  key: SecretInput,
  replayWindow: ReplayWindowHandle,
): AuthenticatedFrame;
export function processZeroRttDatagram(
  datagram: Buffer,
  secretKey: SecretInput,
  targetKeyId: bigint,
  replayWindow: ReplayWindowHandle,
): {
  status: string;
  streamId: number;
  sequenceNumber: bigint;
  plaintext: Buffer;
};
export function processZeroRttDatagramInPlace(
  datagram: Buffer,
  secretKey: SecretInput,
  targetKeyId: bigint,
  replayWindow: ReplayWindowHandle,
): InPlaceZeroRttResult;

export function createReplayWindow(): ReplayWindowHandle;
export function resetReplayWindow(window: ReplayWindowHandle): void;

export function aeadLock(
  key: SecretInput,
  nonce: Buffer,
  plaintext: Buffer,
  aad?: Buffer | null,
): Buffer;
export function aeadUnlock(
  key: SecretInput,
  nonce: Buffer,
  sealed: Buffer,
  aad?: Buffer | null,
): Buffer;
export function aeadUnlockInPlace(
  key: SecretInput,
  nonce: Buffer,
  sealed: Buffer,
  aad?: Buffer | null,
): InPlacePlaintextResult;

export function createOneRttState(
  baseNonce: Buffer,
  initialTxSeq?: bigint,
): OneRttStateHandle;
export function resetOneRttReplayWindow(state: OneRttStateHandle): void;
export function destroyOneRttState(state: OneRttStateHandle): void;
export function sealOneRttFrame(
  key: SecretInput,
  state: OneRttStateHandle,
  plaintext: Buffer,
  aad?: Buffer | null,
): OneRttSealResult;
export function openOneRttFrame(
  key: SecretInput,
  state: OneRttStateHandle,
  sequenceNumber: bigint,
  sealed: Buffer,
  aad?: Buffer | null,
): Buffer;
export function openOneRttFrameInPlace(
  key: SecretInput,
  state: OneRttStateHandle,
  sequenceNumber: bigint,
  sealed: Buffer,
  aad?: Buffer | null,
): InPlacePlaintextResult;

export interface ReplayWindowLike {
  inspect(sequenceNumber: bigint): boolean;
  commit(sequenceNumber: bigint): boolean;
  reset?(): void;
}

export class SlidingReplayWindow implements ReplayWindowLike {
  inspect(sequenceNumber: bigint): boolean;
  commit(sequenceNumber: bigint): boolean;
  reset(): void;
}

export interface OneRttSessionOptions {
  baseNonce?: Buffer;
  initialTxSeq?: bigint;
  replayWindow?: ReplayWindowLike;
  ownsKey?: boolean;
}

export class OneRttSession {
  constructor(
    addon: unknown,
    key: SecretInput,
    options?: OneRttSessionOptions,
  );
  readonly nextTxSequence: bigint;
  readonly isDisposed: boolean;
  seal(plaintext: Buffer, aad?: Buffer | null): OneRttSealResult;
  open(sequenceNumber: bigint, sealed: Buffer, aad?: Buffer | null): Buffer;
  openInPlace(
    sequenceNumber: bigint,
    sealedBuffer: Buffer,
    aad?: Buffer | null,
  ): InPlacePlaintextResult;
  destroy(): void;
  [Symbol.dispose](): void;
}

export interface EpochSlot<W = ReplayWindowHandle | null> {
  readonly epoch: number;
  readonly publicKey: Buffer;
  readonly secretKey: SecureSecretHandle;
  readonly replayWindow: W;
  readonly createdAt: number;
}

export interface EpochLease<W = ReplayWindowHandle | null> extends EpochSlot<W> {
  release(): void;
  [Symbol.dispose](): void;
}

export interface EpochKeyManagerOptions<W = ReplayWindowHandle | null> {
  initialEpoch?: number;
  createReplayWindow?: (epoch: number) => W;
  onRotationError?: (error: Error) => void;
}

export class EpochKeyManager<W = ReplayWindowHandle | null> {
  constructor(addon: unknown, options?: EpochKeyManagerOptions<W>);
  readonly isDisposed: boolean;
  getPublicAdvertisement(): { epoch: number; publicKey: Buffer };
  rotate(nextEpoch?: number): { epoch: number; publicKey: Buffer };
  expirePrevious(): boolean;
  resolveEpoch(epochId: number): EpochSlot<W> | null;
  acquireEpoch(epochId: number): EpochLease<W> | null;
  startAutoRotation(intervalMs: number): void;
  stopAutoRotation(): void;
  destroy(): void;
  [Symbol.dispose](): void;
}
