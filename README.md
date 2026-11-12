[![CI — Native Build, VmLck Telemetry & Contract Gate](https://github.com/bradglenn6/lattice-wire-native/actions/workflows/ci.yml/badge.svg)](https://github.com/bradglenn6/lattice-wire-native/actions/workflows/ci.yml)

# `@zerolabz/lattice-wire-native`

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
   * `EpochKeyManager` maintains at most two active ML-KEM-512 epoch key slots (`#current` and `#previous`), retiring `#previous` prior to allocating a replacement epoch so locked memory never exceeds **2 OS pages** (`8 KB` on `x86_64`), while protecting in-flight 0-RTT decapsulations via `acquireEpoch()` reference leases.

---

## Wire Format (`SPEC-LATTICE-WIRE-01` / `02`)

### 0-RTT Datagram Layout (`812-Byte` Header AAD + Variable Payload + `16-Byte` Tag)

```text
+-----------------------------------------------------------------------+
|  0..3    MagicU32          (4B)  : 0x4C573031 ("LW01")                |
|  4..7    KeyEpochId        (4B)  : Big-Endian uint32 Epoch ID         |
|  8..15   StreamId          (8B)  : Big-Endian uint64 Stream ID        |
| 16..31   ClientDstKeyId   (16B)  : 128-bit Routing / Destination ID   |
| 32..43   Nonce96          (12B)  : 96-bit Packet Nonce / Base IV      |
| 44..811  KemCiphertext   (768B)  : FIPS 203 ML-KEM-512 Ciphertext     |
+-----------------------------------------------------------------------+
| 812..N   Ciphertext      (Var)   : ChaCha20 Encrypted Payload         |
| N..N+16  Poly1305Tag     (16B)   : 128-bit Authentication Tag         |
+-----------------------------------------------------------------------+