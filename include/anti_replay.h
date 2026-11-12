#pragma once

#include <cstdint>
#include <mutex>

namespace lattice_wire {

enum class ReplayStatus : std::uint8_t {
  kAcceptable,
  kDuplicate,
  kTooOld
};

class TwoPhaseAntiReplay final {
 public:
  static constexpr std::uint64_t kWindowSize = 64;

  struct Snapshot {
    bool initialized;
    std::uint64_t max_sequence;
    std::uint64_t bitmap;
  };

  ReplayStatus Inspect(std::uint64_t sequence) const;
  bool CommitAfterAuthentication(std::uint64_t sequence);
  Snapshot GetSnapshot() const;
  void Reset();

 private:
  static ReplayStatus InspectSnapshot(std::uint64_t sequence,
                                      const Snapshot& snapshot);

  mutable std::mutex mutex_;
  Snapshot state_{false, 0, 0};
};

}  // namespace lattice_wire
