#include "aead_chacha20poly1305.h"

#include "monocypher.h"

namespace lattice_wire {
namespace {

const std::uint8_t* NonNullData(std::span<const std::uint8_t> data,
                                const std::uint8_t* empty) {
  return data.empty() ? empty : data.data();
}

std::uint8_t* NonNullData(std::span<std::uint8_t> data, std::uint8_t* empty) {
  return data.empty() ? empty : data.data();
}

}  // namespace

bool AeadDecrypt(
    std::span<const std::uint8_t, kAeadKeySize> key,
    std::span<const std::uint8_t, kAeadNonceSize> nonce,
    std::span<const std::uint8_t> associated_data,
    std::span<const std::uint8_t> ciphertext,
    std::span<const std::uint8_t, kAeadTagSize> tag,
    std::span<std::uint8_t> plaintext) noexcept {
  if (plaintext.size() != ciphertext.size()) {
    return false;
  }

  std::uint8_t empty_input = 0;
  std::uint8_t empty_output = 0;
  crypto_aead_ctx context{};
  crypto_aead_init_ietf(&context, key.data(), nonce.data());
  const int status = crypto_aead_read(
      &context, NonNullData(plaintext, &empty_output), tag.data(),
      NonNullData(associated_data, &empty_input), associated_data.size(),
      NonNullData(ciphertext, &empty_input), ciphertext.size());
  crypto_wipe(&context, sizeof(context));
  crypto_wipe(&empty_output, sizeof(empty_output));
  crypto_wipe(&empty_input, sizeof(empty_input));
  return status == 0;
}

bool AeadDecryptInPlace(
    std::span<const std::uint8_t, kAeadKeySize> key,
    std::span<const std::uint8_t, kAeadNonceSize> nonce,
    std::span<const std::uint8_t> associated_data,
    std::span<std::uint8_t> ciphertext_and_plaintext,
    std::span<const std::uint8_t, kAeadTagSize> tag) noexcept {
  std::uint8_t empty_input = 0;
  crypto_aead_ctx context{};
  crypto_aead_init_ietf(&context, key.data(), nonce.data());
  const int status = crypto_aead_read(
      &context,
      NonNullData(ciphertext_and_plaintext, &empty_input), tag.data(),
      NonNullData(associated_data, &empty_input), associated_data.size(),
      NonNullData(std::span<const std::uint8_t>(ciphertext_and_plaintext),
                  &empty_input),
      ciphertext_and_plaintext.size());
  crypto_wipe(&context, sizeof(context));
  crypto_wipe(&empty_input, sizeof(empty_input));
  return status == 0;
}

bool AeadEncrypt(
    std::span<const std::uint8_t, kAeadKeySize> key,
    std::span<const std::uint8_t, kAeadNonceSize> nonce,
    std::span<const std::uint8_t> associated_data,
    std::span<const std::uint8_t> plaintext,
    std::span<std::uint8_t> ciphertext,
    std::span<std::uint8_t, kAeadTagSize> tag) noexcept {
  if (ciphertext.size() != plaintext.size()) {
    crypto_wipe(tag.data(), tag.size());
    return false;
  }

  std::uint8_t empty_input = 0;
  std::uint8_t empty_output = 0;
  crypto_aead_ctx context{};
  crypto_aead_init_ietf(&context, key.data(), nonce.data());
  crypto_aead_write(
      &context, NonNullData(ciphertext, &empty_output), tag.data(),
      NonNullData(associated_data, &empty_input), associated_data.size(),
      NonNullData(plaintext, &empty_input), plaintext.size());
  crypto_wipe(&context, sizeof(context));
  crypto_wipe(&empty_output, sizeof(empty_output));
  crypto_wipe(&empty_input, sizeof(empty_input));
  return true;
}

}  // namespace lattice_wire
