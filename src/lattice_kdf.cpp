#include "lattice_kdf.h"

#include <algorithm>

#include "monocypher.h"

extern "C" {
#include "fips202.h"
}

namespace lattice_wire {
namespace {

constexpr std::array<std::uint8_t, 23> kDomain = {
    'Z', 'e', 'r', 'o', 'L', 'a', 'b', 'z', '-', 'L', 'a', 't',
    't', 'i', 'c', 'e', 'W', 'i', 'r', 'e', '-', 'v', '1'};

void WriteU32Be(std::uint8_t* output, std::uint32_t value) {
  for (int i = 3; i >= 0; --i) {
    output[i] = static_cast<std::uint8_t>(value);
    value >>= 8;
  }
}

void WriteU64Be(std::uint8_t* output, std::uint64_t value) {
  for (int i = 7; i >= 0; --i) {
    output[i] = static_cast<std::uint8_t>(value);
    value >>= 8;
  }
}

}  // namespace

void DeriveAeadKey(
    std::span<const std::uint8_t, 32> candidate_shared_secret,
    std::uint64_t destination_key_id,
    std::uint32_t stream_id,
    std::span<const std::uint8_t, 12> nonce,
    std::span<std::uint8_t, kLatticeAeadKeySize> aead_key) noexcept {
  std::array<std::uint8_t, 79> input{};
  std::size_t offset = 0;
  std::copy(kDomain.begin(), kDomain.end(), input.begin() + offset);
  offset += kDomain.size();
  std::copy(candidate_shared_secret.begin(), candidate_shared_secret.end(),
            input.begin() + offset);
  offset += candidate_shared_secret.size();
  WriteU64Be(input.data() + offset, destination_key_id);
  offset += sizeof(destination_key_id);
  WriteU32Be(input.data() + offset, stream_id);
  offset += sizeof(stream_id);
  std::copy(nonce.begin(), nonce.end(), input.begin() + offset);
  offset += nonce.size();

  shake256(aead_key.data(), aead_key.size(), input.data(), offset);
  crypto_wipe(input.data(), input.size());
}

}  // namespace lattice_wire
