#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace lattice_wire {

inline constexpr std::size_t kLatticeAeadKeySize = 32;

void DeriveAeadKey(
    std::span<const std::uint8_t, 32> candidate_shared_secret,
    std::uint64_t destination_key_id,
    std::uint32_t stream_id,
    std::span<const std::uint8_t, 12> nonce,
    std::span<std::uint8_t, kLatticeAeadKeySize> aead_key) noexcept;

}  // namespace lattice_wire
