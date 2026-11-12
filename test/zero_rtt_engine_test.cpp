#ifdef NDEBUG
#undef NDEBUG
#endif

#include "zero_rtt_engine.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <span>
#include <vector>

#include "aead_chacha20poly1305.h"
#include "lattice_kdf.h"
#include "lattice_wire.h"
#include "mlkem512_wrapper.h"
#include "monocypher.h"

namespace {

void WriteU16(std::uint8_t* output, std::uint16_t value) {
  output[0] = static_cast<std::uint8_t>(value >> 8);
  output[1] = static_cast<std::uint8_t>(value);
}

void WriteU32(std::uint8_t* output, std::uint32_t value) {
  for (int i = 3; i >= 0; --i) {
    output[i] = static_cast<std::uint8_t>(value);
    value >>= 8;
  }
}

void WriteU64(std::uint8_t* output, std::uint64_t value) {
  for (int i = 7; i >= 0; --i) {
    output[i] = static_cast<std::uint8_t>(value);
    value >>= 8;
  }
}

void TestKdfKnownAnswer() {
  using namespace lattice_wire;
  std::array<std::uint8_t, 32> shared_secret{};
  for (std::size_t i = 0; i < shared_secret.size(); ++i) {
    shared_secret[i] = static_cast<std::uint8_t>(i);
  }
  const std::array<std::uint8_t, 12> nonce{
      0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
      0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B};
  std::array<std::uint8_t, kLatticeAeadKeySize> key{};
  DeriveAeadKey(shared_secret, 0x0102030405060708ULL, 0x11223344, nonce,
                key);
  const std::array<std::uint8_t, kLatticeAeadKeySize> expected{
      0xE4, 0xB5, 0xED, 0xE5, 0x70, 0xDA, 0xAA, 0xB6,
      0x1E, 0x8D, 0xBA, 0x78, 0x08, 0x02, 0x9F, 0x2D,
      0xC2, 0xA8, 0xF5, 0xA8, 0x38, 0x75, 0x58, 0xF3,
      0x0E, 0x29, 0x2A, 0x87, 0xC0, 0x47, 0xD1, 0x26};
  assert(key == expected);
  crypto_wipe(shared_secret.data(), shared_secret.size());
  crypto_wipe(key.data(), key.size());
}

std::vector<std::uint8_t> SealFrame(
    std::span<const std::uint8_t, lattice_wire::MlKem512::kPublicKeySize>
        public_key,
    std::uint64_t destination_key_id,
    std::uint32_t stream_id,
    std::uint64_t sequence_number,
    std::span<const std::uint8_t> plaintext) {
  using namespace lattice_wire;
  std::vector<std::uint8_t> frame(kMinFrameSize + plaintext.size());
  frame[0] = 0x5A;
  frame[1] = 0x4C;
  frame[2] = kVersion;
  WriteU32(frame.data() + 4, stream_id);
  WriteU64(frame.data() + 8, sequence_number);
  WriteU64(frame.data() + 16, destination_key_id);
  WriteU16(frame.data() + 24,
           static_cast<std::uint16_t>(plaintext.size()));
  WriteU16(frame.data() + 26, static_cast<std::uint16_t>(kHeaderSize));

  std::array<std::uint8_t, MlKem512::kCiphertextSize> kem_ciphertext{};
  std::array<std::uint8_t, MlKem512::kSharedSecretSize> shared_secret{};
  assert(MlKem512::Encapsulate(
      public_key, kem_ciphertext, shared_secret));
  std::copy(kem_ciphertext.begin(), kem_ciphertext.end(),
            frame.begin() + kHeaderSize);
  crypto_wipe(kem_ciphertext.data(), kem_ciphertext.size());

  std::array<std::uint8_t, kAeadNonceSize> nonce{};
  nonce[0] = static_cast<std::uint8_t>(sequence_number >> 56);
  nonce[1] = static_cast<std::uint8_t>(sequence_number >> 48);
  nonce[2] = static_cast<std::uint8_t>(sequence_number >> 40);
  nonce[3] = static_cast<std::uint8_t>(sequence_number >> 32);
  nonce[4] = static_cast<std::uint8_t>(sequence_number >> 24);
  nonce[5] = static_cast<std::uint8_t>(sequence_number >> 16);
  nonce[6] = static_cast<std::uint8_t>(sequence_number >> 8);
  nonce[7] = static_cast<std::uint8_t>(sequence_number);
  std::copy(nonce.begin(), nonce.end(),
            frame.begin() + kHeaderSize + kKemCiphertextSize);

  std::array<std::uint8_t, kAeadKeySize> aead_key{};
  DeriveAeadKey(shared_secret, destination_key_id, stream_id, nonce, aead_key);
  crypto_wipe(shared_secret.data(), shared_secret.size());

  const std::size_t payload_offset =
      kHeaderSize + kKemCiphertextSize + kNonceSize;
  const std::span<std::uint8_t> ciphertext(frame.data() + payload_offset,
                                           plaintext.size());
  const std::span<std::uint8_t, kAeadTagSize> tag(
      frame.data() + payload_offset + plaintext.size(), kAeadTagSize);
  assert(AeadEncrypt(
      aead_key, nonce,
      std::span<const std::uint8_t>(frame.data(), payload_offset), plaintext,
      ciphertext, tag));
  crypto_wipe(aead_key.data(), aead_key.size());
  return frame;
}

void TestAuthenticatedPipelineAndReplayOrdering() {
  using namespace lattice_wire;
  constexpr std::uint64_t kDestinationKeyId = 0x0102030405060708ULL;
  constexpr std::uint32_t kStreamId = 19;
  constexpr std::uint64_t kSequence = 42;
  std::array<std::uint8_t, MlKem512::kPublicKeySize> public_key{};
  std::array<std::uint8_t, MlKem512::kSecretKeySize> secret_key{};
  assert(MlKem512::Keypair(public_key, secret_key));
  const std::array<std::uint8_t, 9> message{
      'z', 'e', 'r', 'o', '-', 'r', 't', 't', '!'};
  auto frame = SealFrame(public_key, kDestinationKeyId, kStreamId, kSequence,
                         message);
  TwoPhaseAntiReplay replay_window;
  std::array<std::uint8_t, kMaxPayloadSize> plaintext{};

  auto altered_tag = frame;
  altered_tag.back() ^= 0x80;
  auto rejected = ProcessZeroRttDatagram(
      altered_tag, secret_key, kDestinationKeyId, replay_window, plaintext);
  assert(rejected.status == ZeroRttStatus::kAuthenticationFailed);
  assert(replay_window.Inspect(kSequence) == ReplayStatus::kAcceptable);
  for (const auto value : plaintext) {
    assert(value == 0);
  }

  auto altered_kem_ciphertext = frame;
  altered_kem_ciphertext[kHeaderSize] ^= 0x01;
  rejected = ProcessZeroRttDatagram(
      altered_kem_ciphertext, secret_key, kDestinationKeyId, replay_window,
      plaintext);
  assert(rejected.status == ZeroRttStatus::kAuthenticationFailed);
  assert(replay_window.Inspect(kSequence) == ReplayStatus::kAcceptable);

  auto wrong_destination = ProcessZeroRttDatagram(
      frame, secret_key, kDestinationKeyId + 1, replay_window, plaintext);
  assert(wrong_destination.status == ZeroRttStatus::kWrongDestination);
  assert(replay_window.Inspect(kSequence) == ReplayStatus::kAcceptable);

  auto accepted = ProcessZeroRttDatagram(
      frame, secret_key, kDestinationKeyId, replay_window, plaintext);
  assert(accepted.status == ZeroRttStatus::kAuthenticated);
  assert(accepted.stream_id == kStreamId);
  assert(accepted.sequence_number == kSequence);
  assert(accepted.plaintext_size == message.size());
  assert(std::equal(message.begin(), message.end(), plaintext.begin()));
  assert(replay_window.Inspect(kSequence) == ReplayStatus::kDuplicate);

  auto duplicate = ProcessZeroRttDatagram(
      frame, secret_key, kDestinationKeyId, replay_window, plaintext);
  assert(duplicate.status == ZeroRttStatus::kReplayRejected);
  crypto_wipe(secret_key.data(), secret_key.size());
  crypto_wipe(plaintext.data(), plaintext.size());
}

}  // namespace

int main() {
  TestKdfKnownAnswer();
  TestAuthenticatedPipelineAndReplayOrdering();
  std::cout << "Zero-RTT ML-KEM/AEAD ingestion tests passed.\n";
}
