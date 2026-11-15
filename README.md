# @zerolabz/wire

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23893473.svg)](https://doi.org/10.5281/zenodo.23893473) [![npm version](https://img.shields.io/npm/v/@zerolabz/wire.svg)](https://www.npmjs.com/package/@zerolabz/wire) [![CI](https://github.com/bradglenn6/lattice-wire-native/actions/workflows/ci.yml/badge.svg)](https://github.com/bradglenn6/lattice-wire-native/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

High-assurance, zero-V8-residency post-quantum 0-RTT and 1-RTT transport engine for Node.js.

`lattice-wire-native` implements `SPEC-LATTICE-WIRE-01` and `SPEC-LATTICE-WIRE-02` as a C/C++20 Node-API (`N-API`) native addon. It pairs **FIPS 203 ML-KEM-512** (vendored PQClean clean implementation), a domain-separated **SHAKE-256 KDF**, and **RFC 8439 ChaCha20-Poly1305 AEAD** (Monocypher 4.0.3) with a page-aligned `mmap` + `mlock` (`MADV_DONTDUMP`) secure allocator so Critical Security Parameters (CSPs) never reside on the V8 JavaScript heap.

---

## Core Security Guarantees

1. **Zero V8 Heap Residency for CSPs (`{ secureHandle: true }`)**
   * ML-KEM-512 secret keys (`1,632 bytes`), KEM shared secrets (`32 bytes`), and derived 0-RTT/1-RTT ChaCha20-Poly1305 session keys (`32 bytes`) are generated, derived, and consumed directly inside page-aligned native memory wrapped by type-tagged Node-API `External` handles (`SECURE_SECRET_TYPE_TAG`).
   * Secrets are never staged in V8 `Buffer` objects, protecting against V8 heap snapshots, garbage-collector copying/relocation, and accidental buffer serialization.
2. **Swap & Core-Dump Exclusion (`mlock` + `MADV_DONTDUMP`)**
   * Every secure handle allocation is page-aligned (`mmap` with `MAP_PRIVATE | MAP_ANONYMOUS` on POSIX, `VirtualAlloc` on Windows), pinned in physical RAM via `mlock` (`VirtualLock` on Windows) to prevent swap-file leakage, and marked `MADV_DONTDUMP` on Linux so core dumps omit secret pages.
3. **Deterministic Zeroization (`destroySecret`)**
   * Calling `destroySecret(handle)` (or `session.destroy()` / `manager.destroy()`) immediately scrubs the underlying page via constant-time `crypto_wipe` before invoking `munlock` and `munmap`. Subsequent attempts to use a destroyed handle fail deterministically with `ERR_SECRET_DESTROYED`.
4. **Two-Phase Inspect-Then-Commit Replay Protection**
   * Both the 0-RTT datagram engine and the fused 1-RTT frame pipeline inspect the sliding replay window *before* running ChaCha20-Poly1305 verification and commit the sequence/nonce state *only after* the 16-byte Poly1305 MAC authenticates. Forged packets cannot advance or poison the replay window, and in-place decryption wipes the buffer if a concurrent replay commit fails.
5. **Bounded `RLIMIT_MEMLOCK` Footprint (`EpochKeyManager`)**
   * Pre-allocates active, previous, and next epoch keys inside a single unified locked memory pool, guaranteeing total locked RAM stays strictly bounded within unprivileged shell limits (`ulimit -l` defaults down to 64 KiB).
