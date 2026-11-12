#pragma once

#include <cstddef>
#include <cstdint>

namespace lattice_wire {

inline constexpr std::uint16_t kMagic = 0x5A4C;
inline constexpr std::uint8_t kVersion = 1;
inline constexpr std::size_t kHeaderSize = 32;
inline constexpr std::size_t kKemCiphertextSize = 768;
inline constexpr std::size_t kNonceSize = 12;
inline constexpr std::size_t kTagSize = 16;
inline constexpr std::size_t kMaxPayloadSize = 644;
inline constexpr std::size_t kMinFrameSize =
    kHeaderSize + kKemCiphertextSize + kNonceSize + kTagSize;
inline constexpr std::size_t kMaxFrameSize = kMinFrameSize + kMaxPayloadSize;

struct FrameMetadata {
  std::uint32_t stream_id;
  std::uint64_t sequence_number;
  std::uint64_t destination_key_id;
  std::uint16_t payload_length;
};

struct FrameView {
  FrameMetadata metadata;
  const std::uint8_t* header;
  const std::uint8_t* kem_ciphertext;
  const std::uint8_t* nonce;
  const std::uint8_t* encrypted_payload;
  const std::uint8_t* tag;
};

enum class FrameError {
  kNone,
  kNullData,
  kTooShort,
  kTooLarge,
  kBadMagic,
  kUnsupportedVersion,
  kReservedFlags,
  kBadHeaderLength,
  kNonzeroReserved,
  kPayloadTooLarge,
  kInvalidAckLength,
  kLengthMismatch
};

FrameError ValidateFrame(const std::uint8_t* data, std::size_t size,
                         FrameMetadata* metadata);
FrameError ParseFrame(const std::uint8_t* data, std::size_t size,
                      FrameView* view);

}  // namespace lattice_wire
