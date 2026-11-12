#ifdef NDEBUG
#undef NDEBUG
#endif

#include "mlkem512_wrapper.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>

using lattice_wire::MlKem512;

void TestRoundTrip() {
  std::array<std::uint8_t, MlKem512::kPublicKeySize> public_key{};
  std::array<std::uint8_t, MlKem512::kSecretKeySize> secret_key{};
  std::array<std::uint8_t, MlKem512::kCiphertextSize> ciphertext{};
  std::array<std::uint8_t, MlKem512::kSharedSecretSize> encapsulated_secret{};
  std::array<std::uint8_t, MlKem512::kSharedSecretSize> decapsulated_secret{};

  assert(MlKem512::Keypair(public_key, secret_key));
  assert(MlKem512::Encapsulate(public_key, ciphertext, encapsulated_secret));
  assert(MlKem512::Decapsulate(ciphertext, secret_key, decapsulated_secret));
  assert(encapsulated_secret == decapsulated_secret);
}

void TestImplicitRejection() {
  std::array<std::uint8_t, MlKem512::kPublicKeySize> public_key{};
  std::array<std::uint8_t, MlKem512::kSecretKeySize> secret_key{};
  std::array<std::uint8_t, MlKem512::kCiphertextSize> ciphertext{};
  std::array<std::uint8_t, MlKem512::kSharedSecretSize> valid_secret{};
  std::array<std::uint8_t, MlKem512::kSharedSecretSize> rejected_secret{};

  assert(MlKem512::Keypair(public_key, secret_key));
  assert(MlKem512::Encapsulate(public_key, ciphertext, valid_secret));
  ciphertext[100] ^= 0x55;

  // ML-KEM decapsulation succeeds with an implicit-rejection secret. The
  // decapsulation API does not expose a ciphertext-validity boolean.
  assert(MlKem512::Decapsulate(ciphertext, secret_key, rejected_secret));
  assert(valid_secret != rejected_secret);
}

int main() {
  TestRoundTrip();
  TestImplicitRejection();
  std::cout << "ML-KEM-512 wrapper tests passed.\n";
}
