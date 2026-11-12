#include "mlkem512_wrapper.h"

#include <array>

#include "monocypher.h"
#include "randombytes.h"

extern "C" {
#include "kem.h"
}

namespace lattice_wire {

bool MlKem512::Keypair(
    std::span<std::uint8_t, kPublicKeySize> public_key,
    std::span<std::uint8_t, kSecretKeySize> secret_key) noexcept {
  std::array<std::uint8_t, 64> coins{};
  if (randombytes(coins.data(), coins.size()) != 0) {
    crypto_wipe(public_key.data(), public_key.size());
    crypto_wipe(secret_key.data(), secret_key.size());
    crypto_wipe(coins.data(), coins.size());
    return false;
  }

  const int status = PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(
      public_key.data(), secret_key.data(), coins.data());
  crypto_wipe(coins.data(), coins.size());
  if (status != 0) {
    crypto_wipe(public_key.data(), public_key.size());
    crypto_wipe(secret_key.data(), secret_key.size());
    return false;
  }
  return true;
}

bool MlKem512::Encapsulate(
    std::span<const std::uint8_t, kPublicKeySize> public_key,
    std::span<std::uint8_t, kCiphertextSize> ciphertext,
    std::span<std::uint8_t, kSharedSecretSize> shared_secret) noexcept {
  std::array<std::uint8_t, 32> coins{};
  if (randombytes(coins.data(), coins.size()) != 0) {
    crypto_wipe(ciphertext.data(), ciphertext.size());
    crypto_wipe(shared_secret.data(), shared_secret.size());
    crypto_wipe(coins.data(), coins.size());
    return false;
  }

  const int status = PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(
      ciphertext.data(), shared_secret.data(), public_key.data(), coins.data());
  crypto_wipe(coins.data(), coins.size());
  if (status != 0) {
    crypto_wipe(ciphertext.data(), ciphertext.size());
    crypto_wipe(shared_secret.data(), shared_secret.size());
    return false;
  }
  return true;
}

bool MlKem512::Decapsulate(
    std::span<const std::uint8_t, kCiphertextSize> ciphertext,
    std::span<const std::uint8_t, kSecretKeySize> secret_key,
    std::span<std::uint8_t, kSharedSecretSize> shared_secret) noexcept {
  const int status = PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(
      shared_secret.data(), ciphertext.data(), secret_key.data());
  if (status != 0) {
    crypto_wipe(shared_secret.data(), shared_secret.size());
  }
  return status == 0;
}

}  // namespace lattice_wire
