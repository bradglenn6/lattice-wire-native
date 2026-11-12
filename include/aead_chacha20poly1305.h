#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace lattice_wire {

inline constexpr std::size_t kAeadKeySize = 32;
inline constexpr std::size_t kAeadNonceSize = 12;
inline constexpr std::size_t kAeadTagSize = 16;

bool AeadDecrypt(
    std::span<const std::uint8_t, kAeadKeySize> key,
    std::span<const std::uint8_t, kAeadNonceSize> nonce,
    std::span<const std::uint8_t> associated_data,
    std::span<const std::uint8_t> ciphertext,
    std::span<const std::uint8_t, kAeadTagSize> tag,
    std::span<std::uint8_t> plaintext) noexcept;

bool AeadDecryptInPlace(
    std::span<const std::uint8_t, kAeadKeySize> key,
    std::span<const std::uint8_t, kAeadNonceSize> nonce,
    std::span<const std::uint8_t> associated_data,
    std::span<std::uint8_t> ciphertext_and_plaintext,
    std::span<const std::uint8_t, kAeadTagSize> tag) noexcept;

bool AeadEncrypt(
    std::span<const std::uint8_t, kAeadKeySize> key,
    std::span<const std::uint8_t, kAeadNonceSize> nonce,
    std::span<const std::uint8_t> associated_data,
    std::span<const std::uint8_t> plaintext,
    std::span<std::uint8_t> ciphertext,
    std::span<std::uint8_t, kAeadTagSize> tag) noexcept;

}  // namespace lattice_wire
