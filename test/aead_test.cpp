#ifdef NDEBUG
#undef NDEBUG
#endif

#include "aead_chacha20poly1305.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include "monocypher.h"

namespace {

template <std::size_t N>
std::array<std::uint8_t, N> Hex(const char (&input)[N * 2 + 1]) {
  const auto nibble = [](char value) -> std::uint8_t {
    if (value >= '0' && value <= '9') {
      return static_cast<std::uint8_t>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
      return static_cast<std::uint8_t>(value - 'a' + 10);
    }
    return static_cast<std::uint8_t>(value - 'A' + 10);
  };
  std::array<std::uint8_t, N> result{};
  for (std::size_t i = 0; i < N; ++i) {
    result[i] = static_cast<std::uint8_t>(
        (nibble(input[i * 2]) << 4) | nibble(input[i * 2 + 1]));
  }
  return result;
}

void TestRfc8439KnownAnswer() {
  using namespace lattice_wire;
  const auto key = Hex<32>(
      "808182838485868788898a8b8c8d8e8f"
      "909192939495969798999a9b9c9d9e9f");
  const auto nonce = Hex<12>("070000004041424344454647");
  const auto aad = Hex<12>("50515253c0c1c2c3c4c5c6c7");
  const auto expected_ciphertext = Hex<114>(
      "d31a8d34648e60db7b86afbc53ef7ec2"
      "a4aded51296e08fea9e2b5a736ee62d6"
      "3dbea45e8ca9671282fafb69da92728b"
      "1a71de0a9e060b2905d6a5b67ecd3b36"
      "92ddbd7f2d778b8c9803aee328091b58"
      "fab324e4fad675945585808b4831d7bc"
      "3ff4def08e4b7a9de576d26586cec64b"
      "6116");
  const auto expected_tag =
      Hex<16>("1ae10b594f09e26a7e902ecbd0600691");
  const std::string plaintext =
      "Ladies and Gentlemen of the class of '99: If I could offer you only "
      "one tip for the future, sunscreen would be it.";

  std::vector<std::uint8_t> ciphertext(plaintext.size());
  std::array<std::uint8_t, kAeadTagSize> tag{};
  assert(AeadEncrypt(
      key, nonce, aad,
      std::span(reinterpret_cast<const std::uint8_t*>(plaintext.data()),
                plaintext.size()),
      ciphertext, tag));
  assert(ciphertext == std::vector<std::uint8_t>(
                           expected_ciphertext.begin(),
                           expected_ciphertext.end()));
  assert(tag == expected_tag);

  std::vector<std::uint8_t> recovered(plaintext.size());
  assert(AeadDecrypt(key, nonce, aad, ciphertext, tag, recovered));
  assert(std::string(recovered.begin(), recovered.end()) == plaintext);
  crypto_wipe(recovered.data(), recovered.size());
}

void TestModifiedInputsAreRejectedWithoutReleasingPlaintext() {
  using namespace lattice_wire;
  const std::array<std::uint8_t, kAeadKeySize> key{};
  const std::array<std::uint8_t, kAeadNonceSize> nonce{};
  const std::array<std::uint8_t, 4> aad{1, 2, 3, 4};
  const std::array<std::uint8_t, 5> plaintext{10, 20, 30, 40, 50};
  std::array<std::uint8_t, 5> ciphertext{};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  assert(AeadEncrypt(key, nonce, aad, plaintext, ciphertext, tag));

  auto bad_tag = tag;
  bad_tag[0] ^= 1;
  std::array<std::uint8_t, 5> output;
  output.fill(0xA5);
  assert(!AeadDecrypt(key, nonce, aad, ciphertext, bad_tag, output));
  assert((output == std::array<std::uint8_t, 5>{0xA5, 0xA5, 0xA5, 0xA5, 0xA5}));

  auto bad_ciphertext = ciphertext;
  bad_ciphertext[0] ^= 1;
  assert(!AeadDecrypt(key, nonce, aad, bad_ciphertext, tag, output));

  auto bad_aad = aad;
  bad_aad[0] ^= 1;
  assert(!AeadDecrypt(key, nonce, bad_aad, ciphertext, tag, output));
}

void TestEmptyPayload() {
  using namespace lattice_wire;
  const std::array<std::uint8_t, kAeadKeySize> key{};
  const std::array<std::uint8_t, kAeadNonceSize> nonce{};
  const std::array<std::uint8_t, 2> aad{0x5A, 0x4C};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  const std::span<const std::uint8_t> empty;
  std::span<std::uint8_t> empty_output;

  assert(AeadEncrypt(key, nonce, aad, empty, empty_output, tag));
  assert(AeadDecrypt(key, nonce, aad, empty, tag, empty_output));
  tag[0] ^= 1;
  assert(!AeadDecrypt(key, nonce, aad, empty, tag, empty_output));
}

}  // namespace

int main() {
  TestRfc8439KnownAnswer();
  TestModifiedInputsAreRejectedWithoutReleasingPlaintext();
  TestEmptyPayload();
  std::cout << "RFC 8439 AEAD tests passed.\n";
}
