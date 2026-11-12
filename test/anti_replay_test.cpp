#ifdef NDEBUG
#undef NDEBUG
#endif

#include "anti_replay.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <thread>

using lattice_wire::ReplayStatus;
using lattice_wire::TwoPhaseAntiReplay;

void TestUnauthenticatedSequenceDoesNotPolluteWindow() {
  TwoPhaseAntiReplay replay;
  assert(replay.Inspect(10) == ReplayStatus::kAcceptable);
  assert(replay.CommitAfterAuthentication(10));

  assert(replay.Inspect(2000) == ReplayStatus::kAcceptable);
  const auto afterUnauthenticatedPacket = replay.GetSnapshot();
  assert(afterUnauthenticatedPacket.initialized);
  assert(afterUnauthenticatedPacket.max_sequence == 10);
  assert(afterUnauthenticatedPacket.bitmap == 1);

  assert(replay.Inspect(11) == ReplayStatus::kAcceptable);
  assert(replay.CommitAfterAuthentication(11));
  assert(replay.GetSnapshot().max_sequence == 11);
}

void TestDuplicatesAndOldSequences() {
  TwoPhaseAntiReplay replay;
  assert(replay.CommitAfterAuthentication(100));
  assert(replay.Inspect(100) == ReplayStatus::kDuplicate);
  assert(!replay.CommitAfterAuthentication(100));
  assert(replay.Inspect(36) == ReplayStatus::kTooOld);
  assert(!replay.CommitAfterAuthentication(36));

  assert(replay.Inspect(99) == ReplayStatus::kAcceptable);
  assert(replay.CommitAfterAuthentication(99));
  assert(replay.Inspect(99) == ReplayStatus::kDuplicate);
}

void TestInitialZeroSequenceAndReset() {
  TwoPhaseAntiReplay replay;
  assert(replay.Inspect(0) == ReplayStatus::kAcceptable);
  assert(replay.CommitAfterAuthentication(0));
  assert(replay.Inspect(0) == ReplayStatus::kDuplicate);

  replay.Reset();
  assert(replay.Inspect(0) == ReplayStatus::kAcceptable);
}

void TestConcurrentDuplicateCommitHasSingleWinner() {
  TwoPhaseAntiReplay replay;
  bool results[2] = {false, false};

  std::thread first([&] { results[0] = replay.CommitAfterAuthentication(42); });
  std::thread second([&] { results[1] = replay.CommitAfterAuthentication(42); });
  first.join();
  second.join();

  assert(results[0] != results[1]);
  assert(replay.GetSnapshot().bitmap == 1);
}

int main() {
  TestUnauthenticatedSequenceDoesNotPolluteWindow();
  TestDuplicatesAndOldSequences();
  TestInitialZeroSequenceAndReset();
  TestConcurrentDuplicateCommitHasSingleWinner();
  std::cout << "Two-phase replay window tests passed.\n";
}
