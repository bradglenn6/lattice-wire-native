#include "lattice_wire.h"

namespace lattice_wire {
namespace {

std::uint16_t ReadU16(const std::uint8_t* data) {
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(data[0]) << 8) |
      static_cast<std::uint16_t>(data[1]));
}

std::uint32_t ReadU32(const std::uint8_t* data) {
  return (static_cast<std::uint32_t>(data[0]) << 24) |
         (static_cast<std::uint32_t>(data[1]) << 16) |
         (static_cast<std::uint32_t>(data[2]) << 8) |
         static_cast<std::uint32_t>(data[3]);
}

std::uint64_t ReadU64(const std::uint8_t* data) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    value = (value << 8) | data[i];
  }
  return value;
}

}  // namespace

FrameError ValidateFrame(const std::uint8_t* data, std::size_t size,
                         FrameMetadata* metadata) {
  if (data == nullptr) {
    return FrameError::kNullData;
  }
  if (size < kMinFrameSize) {
    return FrameError::kTooShort;
  }
  if (size > kMaxFrameSize) {
    return FrameError::kTooLarge;
  }
  if (data[0] != 0x5A || data[1] != 0x4C) {
    return FrameError::kBadMagic;
  }
  if (data[2] != kVersion) {
    return FrameError::kUnsupportedVersion;
  }
  if ((data[3] & 0xFC) != 0) {
    return FrameError::kReservedFlags;
  }
  if (ReadU16(data + 26) != kHeaderSize) {
    return FrameError::kBadHeaderLength;
  }
  if (data[28] != 0 || data[29] != 0 || data[30] != 0 || data[31] != 0) {
    return FrameError::kNonzeroReserved;
  }

  const std::uint16_t payload_length = ReadU16(data + 24);
  if (payload_length > kMaxPayloadSize) {
    return FrameError::kPayloadTooLarge;
  }
  if ((data[3] & 0x01) != 0 && payload_length != 8) {
    return FrameError::kInvalidAckLength;
  }
  if (size != kMinFrameSize + payload_length) {
    return FrameError::kLengthMismatch;
  }

  if (metadata != nullptr) {
    metadata->stream_id = ReadU32(data + 4);
    metadata->sequence_number = ReadU64(data + 8);
    metadata->destination_key_id = ReadU64(data + 16);
    metadata->payload_length = payload_length;
  }
  return FrameError::kNone;
}

FrameError ParseFrame(const std::uint8_t* data, std::size_t size,
                      FrameView* view) {
  if (view == nullptr) {
    return FrameError::kNullData;
  }

  FrameMetadata metadata{};
  const FrameError error = ValidateFrame(data, size, &metadata);
  if (error != FrameError::kNone) {
    return error;
  }

  const std::size_t payload_offset =
      kHeaderSize + kKemCiphertextSize + kNonceSize;
  *view = FrameView{
      metadata,
      data,
      data + kHeaderSize,
      data + kHeaderSize + kKemCiphertextSize,
      data + payload_offset,
      data + payload_offset + metadata.payload_length,
  };
  return FrameError::kNone;
}

}  // namespace lattice_wire
