# Changelog

## [Unreleased] - 2026-11-11

### Added

- **Native secure secret handles (`allocateSecret`, `destroySecret`)**: Added page-rounded native secret storage with locked pages and explicit wiping on destruction. Linux allocations also require `MADV_DONTDUMP`; Windows uses `VirtualLock`.
- **Secure-handle ML-KEM-512 outputs**: Key generation, encapsulation, and decapsulation can write secret outputs directly to secure handles using `true` or `{ secureHandle: true }`. Default Buffer-returning behavior remains available, and decapsulation accepts either a secret-key Buffer or secure handle.
- **Zero-RTT key derivation and sealing**: Added `deriveZeroRttKey` and `sealZeroRttPayload` for the existing wire format, accepting Buffer or secure-handle shared secrets.
- **Standalone ChaCha20-Poly1305 APIs**: Added `aeadLock`, `aeadUnlock`, and `aeadUnlockInPlace` for Buffer or secure-handle keys, including authenticated-failure wiping and in-place tag scrubbing.
- **Native 1-RTT state and session wrapper**: Added native sequence-based nonce construction, a two-phase sliding replay window, fused frame seal/open APIs, and the `OneRttSession` wrapper with support for injected replay windows.
- **Epoch key rotation and leases**: Added `EpochKeyManager` with current/previous key slots, per-epoch replay windows, in-flight leases, optional automatic rotation, and disposal support.
- **Benchmarks, tests, and type declarations**: Added Buffer-versus-handle benchmarks, lifecycle and transport tests, `index.d.ts`, and a zero-dependency runtime contract test.

### Changed

- ML-KEM decapsulation writes shared-secret output directly to its selected destination rather than staging it in an intermediate stack array.
- The package root exports the high-level crypto managers alongside the native addon API.

### Security

- Secure-handle mode reduces V8 heap exposure for secret outputs written directly into native locked allocations. Buffer-based inputs and outputs, caller-held copies, randomness, and other process-memory copies remain outside that protection.
- Secure memory uses operating-system page locking and wiping, but these controls do not guarantee exclusion from every persistence path and do not constitute FIPS 140-3 validation.
- The native replay window authenticates before committing replay state; state ownership and concurrency limitations remain as documented in `SPEC-LATTICE-WIRE-02.md`.
