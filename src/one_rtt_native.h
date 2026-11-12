#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace lattice_wire {

struct OneRttState {
  std::uint8_t base_nonce[12]{};
  std::uint64_t tx_sequence = 0;
  bool tx_exhausted = false;
  std::uint64_t rx_highest_sequence = 0;
  std::uint64_t rx_bitmap = 0;
  bool rx_initialized = false;
};

inline void BuildOneRttNonce(std::uint8_t out_nonce[12],
                             const std::uint8_t base_nonce[12],
                             std::uint64_t sequence) {
  std::memcpy(out_nonce, base_nonce, 4);
  for (std::size_t i = 0; i < 8; ++i) {
    const auto sequence_byte =
        static_cast<std::uint8_t>(sequence >> (56 - i * 8));
    out_nonce[4 + i] = base_nonce[4 + i] ^ sequence_byte;
  }
}

inline bool OneRttReplayInspect(const OneRttState& state,
                                std::uint64_t sequence) {
  if (!state.rx_initialized || sequence > state.rx_highest_sequence) {
    return true;
  }
  const std::uint64_t difference = state.rx_highest_sequence - sequence;
  if (difference >= 64) {
    return false;
  }
  return (state.rx_bitmap & (std::uint64_t{1} << difference)) == 0;
}

inline bool OneRttReplayCommit(OneRttState& state, std::uint64_t sequence) {
  if (!OneRttReplayInspect(state, sequence)) {
    return false;
  }
  if (!state.rx_initialized) {
    state.rx_initialized = true;
    state.rx_highest_sequence = sequence;
    state.rx_bitmap = 1;
    return true;
  }
  if (sequence > state.rx_highest_sequence) {
    const std::uint64_t shift = sequence - state.rx_highest_sequence;
    state.rx_bitmap =
        shift >= 64 ? 1 : (state.rx_bitmap << shift) | std::uint64_t{1};
    state.rx_highest_sequence = sequence;
    return true;
  }
  const std::uint64_t difference = state.rx_highest_sequence - sequence;
  state.rx_bitmap |= std::uint64_t{1} << difference;
  return true;
}

}  // namespace lattice_wire
