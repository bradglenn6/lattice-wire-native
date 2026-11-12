#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "anti_replay.h"
#include "mlkem512_wrapper.h"

namespace lattice_wire {

enum class ZeroRttStatus : std::uint8_t {
  kAuthenticated,
  kInvalidFrame,
  kWrongDestination,
  kReplayRejected,
  kAuthenticationFailed,
  kReplayCommitFailed
};

struct ZeroRttResult {
  ZeroRttStatus status;
  std::uint32_t stream_id;
  std::uint64_t sequence_number;
  std::size_t plaintext_size;
};

ZeroRttResult ProcessZeroRttDatagram(
    std::span<const std::uint8_t> datagram,
    std::span<const std::uint8_t, MlKem512::kSecretKeySize> local_secret_key,
    std::uint64_t local_destination_key_id,
    TwoPhaseAntiReplay& replay_window,
    std::span<std::uint8_t> plaintext_output) noexcept;

ZeroRttResult ProcessZeroRttDatagramInPlace(
    std::span<std::uint8_t> datagram,
    std::span<const std::uint8_t, MlKem512::kSecretKeySize> local_secret_key,
    std::uint64_t local_destination_key_id,
    TwoPhaseAntiReplay& replay_window) noexcept;

}  // namespace lattice_wire
