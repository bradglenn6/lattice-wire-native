#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace lattice_wire {

class MlKem512 final {
 public:
  static constexpr std::size_t kCiphertextSize = 768;
  static constexpr std::size_t kSecretKeySize = 1632;
  static constexpr std::size_t kPublicKeySize = 800;
  static constexpr std::size_t kSharedSecretSize = 32;

  static bool Keypair(
      std::span<std::uint8_t, kPublicKeySize> public_key,
      std::span<std::uint8_t, kSecretKeySize> secret_key) noexcept;

  static bool Encapsulate(
      std::span<const std::uint8_t, kPublicKeySize> public_key,
      std::span<std::uint8_t, kCiphertextSize> ciphertext,
      std::span<std::uint8_t, kSharedSecretSize> shared_secret) noexcept;

  // FIPS 203 decapsulation uses implicit rejection. A true return value means
  // the decapsulation API completed, not that the ciphertext was valid.
  static bool Decapsulate(
      std::span<const std::uint8_t, kCiphertextSize> ciphertext,
      std::span<const std::uint8_t, kSecretKeySize> secret_key,
      std::span<std::uint8_t, kSharedSecretSize> shared_secret) noexcept;
};

}  // namespace lattice_wire
