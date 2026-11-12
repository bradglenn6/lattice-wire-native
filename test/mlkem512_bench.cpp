#include "mlkem512_wrapper.h"

#include <algorithm>
#include <array>
#include <numeric>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <vector>

#include "monocypher.h"

int main() {
  using namespace lattice_wire;
  using Clock = std::chrono::steady_clock;
  constexpr std::size_t kWarmupCount = 100;
  constexpr std::size_t kSampleCount = 5000;

  std::array<std::uint8_t, MlKem512::kPublicKeySize> public_key{};
  std::array<std::uint8_t, MlKem512::kSecretKeySize> secret_key{};
  std::array<std::uint8_t, MlKem512::kCiphertextSize> ciphertext{};
  std::array<std::uint8_t, MlKem512::kSharedSecretSize> encapsulated_secret{};
  std::array<std::uint8_t, MlKem512::kSharedSecretSize> decapsulated_secret{};

  if (!MlKem512::Keypair(public_key, secret_key) ||
      !MlKem512::Encapsulate(public_key, ciphertext, encapsulated_secret)) {
    std::cerr << "ML-KEM setup failed\n";
    return 1;
  }

  for (std::size_t i = 0; i < kWarmupCount; ++i) {
    if (!MlKem512::Decapsulate(ciphertext, secret_key, decapsulated_secret) ||
        decapsulated_secret != encapsulated_secret) {
      std::cerr << "ML-KEM warmup decapsulation failed\n";
      return 1;
    }
  }

  std::vector<std::uint64_t> durations;
  durations.reserve(kSampleCount);
  for (std::size_t i = 0; i < kSampleCount; ++i) {
    const auto start = Clock::now();
    const bool success =
        MlKem512::Decapsulate(ciphertext, secret_key, decapsulated_secret);
    const auto stop = Clock::now();
    if (!success || decapsulated_secret != encapsulated_secret) {
      std::cerr << "ML-KEM measured decapsulation failed\n";
      return 1;
    }
    durations.push_back(static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start)
            .count()));
  }

  std::sort(durations.begin(), durations.end());
  const auto sum = std::accumulate(durations.begin(), durations.end(),
                                   std::uint64_t{0});
  std::cout << "clean ML-KEM-512 decapsulation (ns/op, "
            << kSampleCount << " samples)\n"
            << "min=" << durations.front()
            << " median=" << durations[durations.size() / 2]
            << " p95=" << durations[durations.size() * 95 / 100]
            << " mean=" << sum / durations.size() << '\n';

  crypto_wipe(secret_key.data(), secret_key.size());
  crypto_wipe(encapsulated_secret.data(), encapsulated_secret.size());
  crypto_wipe(decapsulated_secret.data(), decapsulated_secret.size());
  return 0;
}
