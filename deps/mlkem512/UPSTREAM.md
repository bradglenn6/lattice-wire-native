# ML-KEM-512 clean implementation provenance

- Upstream: https://github.com/PQClean/PQClean
- Source revision: `0586a824fc0d49df0b6b6e9179d8d15d06d0974f`
- Upstream path: `crypto_kem/ml-kem-512/clean`
- Shared source files: `common/fips202.c`, `common/fips202.h`,
  `common/compat.h`, `common/randombytes.c`, and `common/randombytes.h`
- Parameter metadata: [META.yml](./META.yml)
- License: [clean/LICENSE](./clean/LICENSE)

**Maintenance notice:** PQClean marked this repository retired and read-only.
This vendored snapshot is not a claim that the implementation is currently
maintained or validated for a production security use. Review the upstream
retirement notice and consider a maintained ML-KEM implementation before
deployment.

The wrapper obtains entropy through PQClean's OS-backed `randombytes` provider,
checks the entropy-provider result, then calls the deterministic key-generation
and encapsulation entry points. It does not use the upstream randomized wrapper
functions, which do not propagate entropy-provider failures.

The pinned metadata also lists an AVX2 variant, but it is a separate
assembly-backed implementation with AVX2, AES, BMI2, and POPCNT requirements;
the metadata lists Linux and macOS support, not MSVC/Windows. It is not an
AVX-512 implementation. This workspace builds the portable clean implementation
on Windows and does not contain a handwritten SIMD replacement. The direct
decapsulation benchmark target measures this clean implementation independently
of Node-API and frame-processing overhead; its results are machine- and
load-dependent and are not performance guarantees.
