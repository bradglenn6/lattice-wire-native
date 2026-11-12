#include "zero_rtt_engine.h"

#include <array>

#include "aead_chacha20poly1305.h"
#include "lattice_kdf.h"
#include "lattice_wire.h"
#include "monocypher.h"

namespace lattice_wire {
namespace {

ZeroRttResult ProcessZeroRttDatagramImpl(
    std::span<const std::uint8_t> datagram,
    std::span<const std::uint8_t, MlKem512::kSecretKeySize> local_secret_key,
    std::uint64_t local_destination_key_id,
    TwoPhaseAntiReplay& replay_window,
    std::span<std::uint8_t> plaintext_output,
    std::span<std::uint8_t> mutable_datagram) noexcept {
  ZeroRttResult result{ZeroRttStatus::kInvalidFrame, 0, 0, 0};
  FrameView frame{};
  if (ParseFrame(datagram.data(), datagram.size(), &frame) != FrameError::kNone) {
    return result;
  }

  const bool in_place = !mutable_datagram.empty();
  const std::size_t payload_size = frame.metadata.payload_length;
  if (in_place) {
    if (mutable_datagram.size() != datagram.size()) {
      return result;
    }
  } else if (plaintext_output.size() < payload_size) {
    return result;
  }

  result.stream_id = frame.metadata.stream_id;
  result.sequence_number = frame.metadata.sequence_number;
  if (frame.metadata.destination_key_id != local_destination_key_id) {
    result.status = ZeroRttStatus::kWrongDestination;
    return result;
  }
  if (replay_window.Inspect(frame.metadata.sequence_number) !=
      ReplayStatus::kAcceptable) {
    result.status = ZeroRttStatus::kReplayRejected;
    return result;
  }

  std::array<std::uint8_t, MlKem512::kSharedSecretSize> candidate_secret{};
  std::array<std::uint8_t, kAeadKeySize> aead_key{};
  const std::span<const std::uint8_t, MlKem512::kCiphertextSize> kem_ciphertext(
      frame.kem_ciphertext, MlKem512::kCiphertextSize);
  if (!MlKem512::Decapsulate(kem_ciphertext, local_secret_key,
                             candidate_secret)) {
    crypto_wipe(candidate_secret.data(), candidate_secret.size());
    result.status = ZeroRttStatus::kAuthenticationFailed;
    return result;
  }

  const std::span<const std::uint8_t, kAeadNonceSize> nonce(
      frame.nonce, kAeadNonceSize);
  DeriveAeadKey(candidate_secret, frame.metadata.destination_key_id,
                frame.metadata.stream_id, nonce, aead_key);
  crypto_wipe(candidate_secret.data(), candidate_secret.size());

  const std::span<const std::uint8_t> associated_data(
      datagram.data(), kHeaderSize + kKemCiphertextSize + kNonceSize);
  const std::span<const std::uint8_t> ciphertext(frame.encrypted_payload,
                                                 payload_size);
  const std::span<const std::uint8_t, kAeadTagSize> tag(frame.tag,
                                                        kAeadTagSize);
  const std::size_t payload_offset =
      kHeaderSize + kKemCiphertextSize + kNonceSize;
  const bool authenticated =
      in_place
          ? AeadDecryptInPlace(
                aead_key, nonce, associated_data,
                mutable_datagram.subspan(payload_offset, payload_size), tag)
          : AeadDecrypt(aead_key, nonce, associated_data, ciphertext, tag,
                        plaintext_output.first(payload_size));
  crypto_wipe(aead_key.data(), aead_key.size());
  if (!authenticated) {
    if (!in_place && payload_size != 0) {
      crypto_wipe(plaintext_output.data(), payload_size);
    }
    result.status = ZeroRttStatus::kAuthenticationFailed;
    return result;
  }

  if (!replay_window.CommitAfterAuthentication(
          frame.metadata.sequence_number)) {
    if (payload_size != 0) {
      crypto_wipe(in_place
                      ? mutable_datagram.data() + payload_offset
                      : plaintext_output.data(),
                  payload_size);
    }
    result.status = ZeroRttStatus::kReplayCommitFailed;
    return result;
  }

  result.status = ZeroRttStatus::kAuthenticated;
  result.plaintext_size = payload_size;
  return result;
}

}  // namespace

ZeroRttResult ProcessZeroRttDatagram(
    std::span<const std::uint8_t> datagram,
    std::span<const std::uint8_t, MlKem512::kSecretKeySize> local_secret_key,
    std::uint64_t local_destination_key_id,
    TwoPhaseAntiReplay& replay_window,
    std::span<std::uint8_t> plaintext_output) noexcept {
  return ProcessZeroRttDatagramImpl(datagram, local_secret_key,
                                    local_destination_key_id, replay_window,
                                    plaintext_output, {});
}

ZeroRttResult ProcessZeroRttDatagramInPlace(
    std::span<std::uint8_t> datagram,
    std::span<const std::uint8_t, MlKem512::kSecretKeySize> local_secret_key,
    std::uint64_t local_destination_key_id,
    TwoPhaseAntiReplay& replay_window) noexcept {
  return ProcessZeroRttDatagramImpl(datagram, local_secret_key,
                                    local_destination_key_id, replay_window,
                                    {}, datagram);
}

}  // namespace lattice_wire
