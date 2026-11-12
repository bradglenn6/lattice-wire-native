#include "anti_replay.h"

namespace lattice_wire {

ReplayStatus TwoPhaseAntiReplay::InspectSnapshot(
    std::uint64_t sequence, const Snapshot& snapshot) {
  if (!snapshot.initialized || sequence > snapshot.max_sequence) {
    return ReplayStatus::kAcceptable;
  }

  const std::uint64_t difference = snapshot.max_sequence - sequence;
  if (difference >= kWindowSize) {
    return ReplayStatus::kTooOld;
  }
  if ((snapshot.bitmap & (std::uint64_t{1} << difference)) != 0) {
    return ReplayStatus::kDuplicate;
  }
  return ReplayStatus::kAcceptable;
}

ReplayStatus TwoPhaseAntiReplay::Inspect(std::uint64_t sequence) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return InspectSnapshot(sequence, state_);
}

bool TwoPhaseAntiReplay::CommitAfterAuthentication(std::uint64_t sequence) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (!state_.initialized) {
    state_ = Snapshot{true, sequence, 1};
    return true;
  }

  if (sequence > state_.max_sequence) {
    const std::uint64_t shift = sequence - state_.max_sequence;
    state_.bitmap = shift >= kWindowSize
                        ? 1
                        : (state_.bitmap << shift) | std::uint64_t{1};
    state_.max_sequence = sequence;
    return true;
  }

  const std::uint64_t difference = state_.max_sequence - sequence;
  if (difference >= kWindowSize) {
    return false;
  }

  const std::uint64_t bit = std::uint64_t{1} << difference;
  if ((state_.bitmap & bit) != 0) {
    return false;
  }

  state_.bitmap |= bit;
  return true;
}

TwoPhaseAntiReplay::Snapshot TwoPhaseAntiReplay::GetSnapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return state_;
}

void TwoPhaseAntiReplay::Reset() {
  std::lock_guard<std::mutex> lock(mutex_);
  state_ = Snapshot{false, 0, 0};
}

}  // namespace lattice_wire
