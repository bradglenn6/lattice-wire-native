import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const nativeAddon = require('./build/Release/lattice_wire_native.node');

export const aeadLock = nativeAddon.aeadLock;
export const aeadUnlock = nativeAddon.aeadUnlock;
export const aeadUnlockInPlace = nativeAddon.aeadUnlockInPlace;
export const allocateSecret = nativeAddon.allocateSecret;
export const createOneRttState = nativeAddon.createOneRttState;
export const createReplayWindow = nativeAddon.createReplayWindow;
export const decapsulateMlKem512 = nativeAddon.decapsulateMlKem512;
export const deriveZeroRttKey = nativeAddon.deriveZeroRttKey;
export const destroyOneRttState = nativeAddon.destroyOneRttState;
export const destroySecret = nativeAddon.destroySecret;
export const encapsulateMlKem512 = nativeAddon.encapsulateMlKem512;
export const generateMlKem512Keypair = nativeAddon.generateMlKem512Keypair;
export const openOneRttFrame = nativeAddon.openOneRttFrame;
export const openOneRttFrameInPlace = nativeAddon.openOneRttFrameInPlace;
export const processAuthenticatedPacket = nativeAddon.processAuthenticatedPacket;
export const processPacket = nativeAddon.processPacket;
export const processZeroRttDatagram = nativeAddon.processZeroRttDatagram;
export const processZeroRttDatagramInPlace =
  nativeAddon.processZeroRttDatagramInPlace;
export const resetOneRttReplayWindow = nativeAddon.resetOneRttReplayWindow;
export const resetReplayWindow = nativeAddon.resetReplayWindow;
export const sealOneRttFrame = nativeAddon.sealOneRttFrame;
export const sealZeroRttPayload = nativeAddon.sealZeroRttPayload;

export { EpochKeyManager } from './lib/crypto/EpochKeyManager.js';
export {
  OneRttSession,
  SlidingReplayWindow,
} from './lib/crypto/OneRttSession.js';
