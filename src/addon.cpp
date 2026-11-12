#include <node_api.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <span>

#include "aead_chacha20poly1305.h"
#include "anti_replay.h"
#include "lattice_kdf.h"
#include "lattice_wire.h"
#include "one_rtt_native.h"
#include "secure_alloc.h"
#include "zero_rtt_engine.h"
#include "monocypher.h"

namespace {

constexpr napi_type_tag kReplayWindowTypeTag = {
    0x7d2c91863f404bc1, 0xa2e5b9610d4f73a8};
constexpr napi_type_tag kSecureSecretTypeTag = {
      0x4ea97c6d3b124c80, 0xb156f32a7d809e41};
constexpr napi_type_tag kOneRttStateTypeTag = {
    0x7a65726f6c61627a, 0x3172747473746174};

bool CheckNapi(napi_env env, napi_status status, const char* message) {
  if (status == napi_ok) {
    return true;
  }
  napi_throw_error(env, nullptr, message);
  return false;
}

bool ThrowErrorWithCode(napi_env env, const char* code, const char* message) {
  napi_value message_value;
  napi_value error;
  napi_value code_value;
  if (!CheckNapi(env, napi_create_string_utf8(
                          env, message, NAPI_AUTO_LENGTH, &message_value),
                 "Unable to create error message") ||
      !CheckNapi(env, napi_create_error(env, nullptr, message_value, &error),
                 "Unable to create error") ||
      !CheckNapi(env, napi_create_string_utf8(
                          env, code, NAPI_AUTO_LENGTH, &code_value),
                 "Unable to create error code") ||
      !CheckNapi(env, napi_set_named_property(env, error, "code", code_value),
                 "Unable to set error code") ||
      !CheckNapi(env, napi_throw(env, error), "Unable to throw error")) {
    return false;
  }
  return false;
}

const char* ErrorMessage(lattice_wire::FrameError error) {
  using lattice_wire::FrameError;
  switch (error) {
    case FrameError::kNone:
      return "";
    case FrameError::kNullData:
      return "Frame data and output view must be non-null";
    case FrameError::kTooShort:
      return "Datagram is shorter than the minimum frame";
    case FrameError::kTooLarge:
      return "Datagram exceeds the maximum frame size";
    case FrameError::kBadMagic:
      return "Invalid frame magic";
    case FrameError::kUnsupportedVersion:
      return "Unsupported frame version";
    case FrameError::kReservedFlags:
      return "Reserved flag bits must be zero";
    case FrameError::kBadHeaderLength:
      return "Header length must be 32";
    case FrameError::kNonzeroReserved:
      return "Reserved header bytes must be zero";
    case FrameError::kPayloadTooLarge:
      return "Payload exceeds the maximum frame size";
    case FrameError::kInvalidAckLength:
      return "ACK_ONLY frames must contain an 8-byte payload";
    case FrameError::kLengthMismatch:
      return "Datagram length does not match the declared payload length";
  }
  return "Invalid frame";
}

struct ReplayWindowHandle {
  lattice_wire::TwoPhaseAntiReplay window;
};

struct SecureSecretHandle {
  secure_alloc_t allocation{};

  ~SecureSecretHandle() { clear_secure_memory(&allocation); }
};

struct OneRttStateHandle {
  lattice_wire::OneRttState state{};
  bool destroyed = false;
};

void FinalizeReplayWindow(napi_env, void* data, void*) {
  delete static_cast<ReplayWindowHandle*>(data);
}

void FinalizeSecureSecret(napi_env, void* data, void*) {
  delete static_cast<SecureSecretHandle*>(data);
}

void FinalizeOneRttState(napi_env, void* data, void*) {
  auto* handle = static_cast<OneRttStateHandle*>(data);
  if (handle != nullptr) {
    crypto_wipe(&handle->state, sizeof(handle->state));
    delete handle;
  }
}

bool GetOneRttState(napi_env env, napi_value value,
                    OneRttStateHandle** handle) {
  bool is_state = false;
  if (!CheckNapi(env, napi_check_object_type_tag(
                          env, value, &kOneRttStateTypeTag, &is_state),
                 "Unable to inspect 1-RTT state handle")) {
    return false;
  }
  if (!is_state) {
    napi_throw_type_error(env, nullptr,
                          "Expected a state handle created by createOneRttState()");
    return false;
  }
  if (!CheckNapi(env, napi_unwrap(env, value,
                                  reinterpret_cast<void**>(handle)),
                 "Unable to access 1-RTT state handle") ||
      *handle == nullptr) {
    return false;
  }
  return true;
}

bool GetUint64BigInt(napi_env env, napi_value value, std::uint64_t* result,
                     const char* message) {
  napi_valuetype value_type;
  if (!CheckNapi(env, napi_typeof(env, value, &value_type),
                 "Unable to inspect sequence number")) {
    return false;
  }
  if (value_type != napi_bigint) {
    napi_throw_type_error(env, nullptr, message);
    return false;
  }
  bool lossless = false;
  if (!CheckNapi(env, napi_get_value_bigint_uint64(env, value, result,
                                                   &lossless),
                 "Unable to read sequence number")) {
    return false;
  }
  if (!lossless) {
    napi_throw_range_error(env, nullptr, message);
    return false;
  }
  return true;
}

bool GetSecureSecretHandle(napi_env env, napi_value value,
                           SecureSecretHandle** handle) {
  bool is_secret = false;
  if (!CheckNapi(env, napi_check_object_type_tag(
                          env, value, &kSecureSecretTypeTag, &is_secret),
                 "Unable to inspect secure secret handle")) {
    return false;
  }
  if (!is_secret) {
    napi_throw_type_error(env, nullptr,
                          "Expected a secure secret handle created by allocateSecret()");
    return false;
  }
  if (!CheckNapi(env, napi_unwrap(env, value,
                                  reinterpret_cast<void**>(handle)),
                 "Unable to access secure secret handle") ||
      *handle == nullptr) {
    return false;
  }
  return true;
}

bool CreateSecureSecretHandle(napi_env env, std::size_t requested_size,
                             SecureSecretHandle** out_handle,
                             napi_value* out_object) {
  *out_handle = nullptr;
  auto* handle = new (std::nothrow) SecureSecretHandle;
  if (handle == nullptr) {
    napi_throw_error(env, nullptr, "Unable to allocate secure secret metadata");
    return false;
  }

  const secure_alloc_result_t allocation_result =
      allocate_secure_memory(requested_size, &handle->allocation);
  if (allocation_result != SECURE_ALLOC_OK) {
    delete handle;
    const char* message = "Unable to allocate locked secure memory";
    if (allocation_result == SECURE_ALLOC_LOCK_FAILED) {
      message = "Unable to lock secure memory; verify process memory-lock limits";
    } else if (allocation_result == SECURE_ALLOC_DONTDUMP_FAILED) {
      message = "Unable to exclude secure memory from Linux core dumps";
    } else if (allocation_result == SECURE_ALLOC_UNSUPPORTED) {
      message = "Secure memory allocation is unsupported on this platform";
    } else if (allocation_result == SECURE_ALLOC_INVALID_SIZE) {
      napi_throw_range_error(env, nullptr, "Secret size must not be empty");
      return false;
    }
    napi_throw_error(env, nullptr, message);
    return false;
  }

  if (!CheckNapi(env, napi_create_object(env, out_object),
                 "Unable to create secure secret handle")) {
    delete handle;
    return false;
  }
  if (!CheckNapi(env, napi_wrap(env, *out_object, handle, FinalizeSecureSecret,
                                nullptr, nullptr),
                 "Unable to initialize secure secret handle")) {
    delete handle;
    return false;
  }
  if (!CheckNapi(env, napi_type_tag_object(env, *out_object,
                                            &kSecureSecretTypeTag),
                 "Unable to tag secure secret handle")) {
    clear_secure_memory(&handle->allocation);
    return false;
  }

  *out_handle = handle;
  return true;
}

bool ParseSecureHandleOption(napi_env env, napi_value value,
                             bool* use_secure_handle) {
  *use_secure_handle = false;
  napi_valuetype value_type;
  if (!CheckNapi(env, napi_typeof(env, value, &value_type),
                 "Unable to inspect secureHandle option")) {
    return false;
  }
  if (value_type == napi_undefined) {
    return true;
  }
  if (value_type == napi_boolean) {
    return CheckNapi(env, napi_get_value_bool(env, value, use_secure_handle),
                     "Unable to read secureHandle option");
  }
  if (value_type != napi_object) {
    napi_throw_type_error(
        env, nullptr,
        "Expected an optional boolean or { secureHandle: boolean }");
    return false;
  }

  napi_value null_value;
  bool is_null = false;
  bool is_array = false;
  bool is_buffer = false;
  if (!CheckNapi(env, napi_get_null(env, &null_value),
                 "Unable to inspect keypair options") ||
      !CheckNapi(env, napi_strict_equals(env, value, null_value, &is_null),
                 "Unable to inspect keypair options") ||
      !CheckNapi(env, napi_is_array(env, value, &is_array),
                 "Unable to inspect keypair options") ||
      !CheckNapi(env, napi_is_buffer(env, value, &is_buffer),
                 "Unable to inspect keypair options")) {
    return false;
  }
  if (is_null || is_array || is_buffer) {
    napi_throw_type_error(
        env, nullptr,
        "Options must be a boolean or a non-null options object");
    return false;
  }

  bool has_secure_handle = false;
  if (!CheckNapi(env, napi_has_named_property(env, value, "secureHandle",
                                              &has_secure_handle),
                 "Unable to inspect secureHandle option")) {
    return false;
  }
  if (!has_secure_handle) {
    return true;
  }

  napi_value option_value;
  napi_valuetype option_type;
  if (!CheckNapi(env, napi_get_named_property(env, value, "secureHandle",
                                               &option_value),
                 "Unable to read secureHandle option") ||
      !CheckNapi(env, napi_typeof(env, option_value, &option_type),
                 "Unable to inspect secureHandle option")) {
    return false;
  }
  if (option_type != napi_boolean) {
    napi_throw_type_error(env, nullptr, "secureHandle option must be a boolean");
    return false;
  }
  return CheckNapi(env, napi_get_value_bool(env, option_value,
                                             use_secure_handle),
                   "Unable to read secureHandle option");
}

bool GetSecretKeyData(napi_env env, napi_value value,
                      std::size_t expected_size,
                      const std::uint8_t** key_data) {
  bool is_buffer = false;
  if (!CheckNapi(env, napi_is_buffer(env, value, &is_buffer),
                 "Unable to inspect secret-key argument")) {
    return false;
  }
  if (is_buffer) {
    void* buffer_data = nullptr;
    std::size_t buffer_size = 0;
    if (!CheckNapi(env, napi_get_buffer_info(env, value, &buffer_data,
                                              &buffer_size),
                   "Unable to access secret-key Buffer")) {
      return false;
    }
    if (buffer_size != expected_size) {
      napi_throw_range_error(
          env, nullptr,
          expected_size == lattice_wire::MlKem512::kSecretKeySize
              ? "ML-KEM-512 secret key must be exactly 1632 bytes"
              : "Shared secret must be exactly 32 bytes");
      return false;
    }
    *key_data = static_cast<const std::uint8_t*>(buffer_data);
    return true;
  }

  napi_valuetype value_type;
  if (!CheckNapi(env, napi_typeof(env, value, &value_type),
                 "Unable to inspect secret-key argument")) {
    return false;
  }
  if (value_type != napi_object) {
    napi_throw_type_error(env, nullptr,
                          "Secret key must be a Buffer or secure secret handle");
    return false;
  }

  SecureSecretHandle* handle = nullptr;
  if (!GetSecureSecretHandle(env, value, &handle)) {
    return false;
  }
  if (handle->allocation.data == nullptr) {
    napi_throw_error(env, nullptr, "Secure secret has already been destroyed");
    return false;
  }
  if (handle->allocation.requested_size != expected_size) {
    napi_throw_range_error(
        env, nullptr,
        expected_size == lattice_wire::MlKem512::kSecretKeySize
            ? "ML-KEM-512 secret key must be exactly 1632 bytes"
            : "Shared secret must be exactly 32 bytes");
    return false;
  }
  *key_data = handle->allocation.data;
  return true;
}

bool GetBufferData(napi_env env, napi_value value, const char* argument_name,
                   void** data, std::size_t* size) {
  bool is_buffer = false;
  if (!CheckNapi(env, napi_is_buffer(env, value, &is_buffer),
                 "Unable to inspect Buffer argument")) {
    return false;
  }
  if (!is_buffer) {
    napi_throw_type_error(env, nullptr, argument_name);
    return false;
  }
  return CheckNapi(env, napi_get_buffer_info(env, value, data, size),
                   "Unable to access Buffer argument");
}

bool GetOptionalAad(napi_env env, napi_value value,
                    const std::uint8_t** aad_data, std::size_t* aad_size) {
  *aad_data = nullptr;
  *aad_size = 0;
  napi_valuetype value_type;
  if (!CheckNapi(env, napi_typeof(env, value, &value_type),
                 "Unable to inspect AAD argument")) {
    return false;
  }
  if (value_type == napi_undefined || value_type == napi_null) {
    return true;
  }

  void* data = nullptr;
  if (!GetBufferData(env, value, "AAD must be a Buffer, null, or undefined",
                     &data, aad_size)) {
    return false;
  }
  if (*aad_size > 0) {
    *aad_data = static_cast<const std::uint8_t*>(data);
  }
  return true;
}

std::uint32_t ReadU32Be(const std::uint8_t* data) {
  return (static_cast<std::uint32_t>(data[0]) << 24) |
         (static_cast<std::uint32_t>(data[1]) << 16) |
         (static_cast<std::uint32_t>(data[2]) << 8) |
         static_cast<std::uint32_t>(data[3]);
}

std::uint64_t ReadU64Be(const std::uint8_t* data) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < sizeof(value); ++i) {
    value = (value << 8) | data[i];
  }
  return value;
}

void DeriveZeroRttAeadKey(
    const std::uint8_t* shared_secret,
    const std::uint8_t* header_aad,
    std::uint8_t* output_key) {
  const std::span<const std::uint8_t, lattice_wire::MlKem512::kSharedSecretSize>
      shared_secret_span(shared_secret,
                         lattice_wire::MlKem512::kSharedSecretSize);
  const std::span<const std::uint8_t, lattice_wire::kNonceSize> nonce(
      header_aad + lattice_wire::kHeaderSize +
          lattice_wire::kKemCiphertextSize,
      lattice_wire::kNonceSize);
  const std::span<std::uint8_t, lattice_wire::kLatticeAeadKeySize> key(
      output_key, lattice_wire::kLatticeAeadKeySize);
  lattice_wire::DeriveAeadKey(
      shared_secret_span,
      ReadU64Be(header_aad + 16),
      ReadU32Be(header_aad + 4),
      nonce,
      key);
}

struct SharedSecretOutput {
  std::uint8_t* data = nullptr;
  napi_value value = nullptr;
  SecureSecretHandle* secure_handle = nullptr;
  bool is_secure = false;
};

bool CreateSharedSecretOutput(napi_env env, bool use_secure_handle,
                              SharedSecretOutput* output) {
  output->is_secure = use_secure_handle;
  if (use_secure_handle) {
    napi_value handle_object;
    if (!CreateSecureSecretHandle(
            env, lattice_wire::MlKem512::kSharedSecretSize,
            &output->secure_handle, &handle_object)) {
      return false;
    }
    output->data = output->secure_handle->allocation.data;
    output->value = handle_object;
    return true;
  }

  void* buffer_data = nullptr;
  if (!CheckNapi(env, napi_create_buffer(
                          env, lattice_wire::MlKem512::kSharedSecretSize,
                          &buffer_data, &output->value),
                 "Unable to allocate ML-KEM shared-secret Buffer")) {
    return false;
  }
  output->data = static_cast<std::uint8_t*>(buffer_data);
  return true;
}

void ClearSharedSecretOutput(SharedSecretOutput* output) {
  if (output->data == nullptr) {
    return;
  }
  if (output->is_secure) {
    clear_secure_memory(&output->secure_handle->allocation);
  } else {
    crypto_wipe(output->data, lattice_wire::MlKem512::kSharedSecretSize);
  }
  output->data = nullptr;
}

napi_value AllocateSecret(napi_env env, napi_callback_info info) {
  std::size_t argc = 1;
  napi_value args[1];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc != 1) {
    napi_throw_type_error(env, nullptr, "Expected one secret Buffer");
    return nullptr;
  }

  bool is_buffer = false;
  if (!CheckNapi(env, napi_is_buffer(env, args[0], &is_buffer),
                 "Unable to inspect secret Buffer")) {
    return nullptr;
  }
  if (!is_buffer) {
    napi_throw_type_error(env, nullptr, "Secret must be a Node.js Buffer");
    return nullptr;
  }

  void* source = nullptr;
  std::size_t source_size = 0;
  if (!CheckNapi(env, napi_get_buffer_info(env, args[0], &source, &source_size),
                 "Unable to access secret Buffer")) {
    return nullptr;
  }

  SecureSecretHandle* handle = nullptr;
  napi_value object;
  if (!CreateSecureSecretHandle(env, source_size, &handle, &object)) {
    return nullptr;
  }
  std::memcpy(handle->allocation.data, source, source_size);
  return object;
}

napi_value DestroySecret(napi_env env, napi_callback_info info) {
  std::size_t argc = 1;
  napi_value args[1];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc != 1) {
    napi_throw_type_error(env, nullptr, "Expected one secure secret handle");
    return nullptr;
  }

  SecureSecretHandle* handle = nullptr;
  if (!GetSecureSecretHandle(env, args[0], &handle)) {
    return nullptr;
  }
  clear_secure_memory(&handle->allocation);

  napi_value undefined;
  return CheckNapi(env, napi_get_undefined(env, &undefined),
                   "Unable to return destroy status")
             ? undefined
             : nullptr;
}

napi_value CreateReplayWindow(napi_env env, napi_callback_info info) {
  napi_value object;
  if (!CheckNapi(env, napi_create_object(env, &object),
                 "Unable to create replay window")) {
    return nullptr;
  }

  auto* handle = new (std::nothrow) ReplayWindowHandle;
  if (handle == nullptr) {
    napi_throw_error(env, nullptr, "Unable to allocate replay window");
    return nullptr;
  }
  if (!CheckNapi(env, napi_wrap(env, object, handle, FinalizeReplayWindow,
                                nullptr, nullptr),
                 "Unable to initialize replay window")) {
    delete handle;
    return nullptr;
  }
  if (!CheckNapi(env, napi_type_tag_object(env, object,
                                            &kReplayWindowTypeTag),
                 "Unable to tag replay window")) {
    return nullptr;
  }
  return object;
}

napi_value ResetReplayWindow(napi_env env, napi_callback_info info) {
  std::size_t argc = 1;
  napi_value args[1];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc != 1) {
    napi_throw_type_error(env, nullptr, "Expected one replay window");
    return nullptr;
  }

  bool is_replay_window = false;
  if (!CheckNapi(env, napi_check_object_type_tag(
                          env, args[0], &kReplayWindowTypeTag,
                          &is_replay_window),
                 "Unable to inspect replay window")) {
    return nullptr;
  }
  if (!is_replay_window) {
    napi_throw_type_error(env, nullptr,
                          "Replay window must be created by createReplayWindow()");
    return nullptr;
  }
  ReplayWindowHandle* replay_window = nullptr;
  if (!CheckNapi(env, napi_unwrap(env, args[0],
                                  reinterpret_cast<void**>(&replay_window)),
                 "Unable to access replay window") ||
      replay_window == nullptr) {
    return nullptr;
  }
  replay_window->window.Reset();
  napi_value undefined;
  return CheckNapi(env, napi_get_undefined(env, &undefined),
                   "Unable to return reset status")
             ? undefined
             : nullptr;
}

napi_value GenerateMlKem512Keypair(napi_env env, napi_callback_info info) {
  std::size_t argc = 2;
  napi_value args[2];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc > 1) {
    napi_throw_type_error(
        env, nullptr,
        "Expected an optional boolean or { secureHandle: boolean }");
    return nullptr;
  }

  bool use_secure_handle = false;
  if (argc == 1) {
    if (!ParseSecureHandleOption(env, args[0], &use_secure_handle)) {
      return nullptr;
    }
  }

  std::array<std::uint8_t, lattice_wire::MlKem512::kPublicKeySize> public_key{};
  if (use_secure_handle) {
    SecureSecretHandle* secure_secret = nullptr;
    napi_value secret_key_handle;
    if (!CreateSecureSecretHandle(
            env, lattice_wire::MlKem512::kSecretKeySize, &secure_secret,
            &secret_key_handle)) {
      return nullptr;
    }

    const std::span<std::uint8_t,
                    lattice_wire::MlKem512::kSecretKeySize>
        secret_key(secure_secret->allocation.data,
                   lattice_wire::MlKem512::kSecretKeySize);
    if (!lattice_wire::MlKem512::Keypair(public_key, secret_key)) {
      crypto_wipe(public_key.data(), public_key.size());
      clear_secure_memory(&secure_secret->allocation);
      napi_throw_error(env, nullptr, "ML-KEM-512 key generation failed");
      return nullptr;
    }

    napi_value result;
    napi_value public_key_buffer;
    void* copied_public_key = nullptr;
    const bool created =
        CheckNapi(env, napi_create_object(env, &result),
                  "Unable to create ML-KEM keypair result") &&
        CheckNapi(env, napi_create_buffer_copy(
                           env, public_key.size(), public_key.data(),
                           &copied_public_key, &public_key_buffer),
                  "Unable to copy ML-KEM public key") &&
        CheckNapi(env, napi_set_named_property(env, result, "publicKey",
                                               public_key_buffer),
                  "Unable to set ML-KEM public key") &&
        CheckNapi(env, napi_set_named_property(env, result, "secretKey",
                                               secret_key_handle),
                  "Unable to set secure ML-KEM secret key");
    crypto_wipe(public_key.data(), public_key.size());
    if (!created) {
      clear_secure_memory(&secure_secret->allocation);
      return nullptr;
    }
    return result;
  }

  std::array<std::uint8_t, lattice_wire::MlKem512::kSecretKeySize> secret_key{};
  if (!lattice_wire::MlKem512::Keypair(public_key, secret_key)) {
    crypto_wipe(public_key.data(), public_key.size());
    crypto_wipe(secret_key.data(), secret_key.size());
    napi_throw_error(env, nullptr, "ML-KEM-512 key generation failed");
    return nullptr;
  }

  napi_value result;
  napi_value public_key_buffer;
  napi_value secret_key_buffer;
  void* copied_public_key = nullptr;
  void* copied_secret_key = nullptr;
  const bool created =
      CheckNapi(env, napi_create_object(env, &result),
                "Unable to create ML-KEM keypair result") &&
      CheckNapi(env, napi_create_buffer_copy(
                         env, public_key.size(), public_key.data(),
                         &copied_public_key, &public_key_buffer),
                "Unable to copy ML-KEM public key") &&
      CheckNapi(env, napi_create_buffer_copy(
                         env, secret_key.size(), secret_key.data(),
                         &copied_secret_key, &secret_key_buffer),
                "Unable to copy ML-KEM secret key") &&
      CheckNapi(env, napi_set_named_property(env, result, "publicKey",
                                             public_key_buffer),
                "Unable to set ML-KEM public key") &&
      CheckNapi(env, napi_set_named_property(env, result, "secretKey",
                                             secret_key_buffer),
                "Unable to set ML-KEM secret key");
  if (!created && copied_secret_key != nullptr) {
    crypto_wipe(copied_secret_key, secret_key.size());
  }
  crypto_wipe(public_key.data(), public_key.size());
  crypto_wipe(secret_key.data(), secret_key.size());
  return created ? result : nullptr;
}

napi_value EncapsulateMlKem512(napi_env env, napi_callback_info info) {
  std::size_t argc = 2;
  napi_value args[2];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc < 1 || argc > 2) {
    napi_throw_type_error(
        env, nullptr,
        "Expected a public-key Buffer and optional secure-handle option");
    return nullptr;
  }

  bool is_buffer = false;
  if (!CheckNapi(env, napi_is_buffer(env, args[0], &is_buffer),
                 "Unable to inspect ML-KEM public key")) {
    return nullptr;
  }
  if (!is_buffer) {
    napi_throw_type_error(env, nullptr,
                          "ML-KEM public key must be a Node.js Buffer");
    return nullptr;
  }

  void* raw_public_key = nullptr;
  std::size_t public_key_size = 0;
  if (!CheckNapi(env, napi_get_buffer_info(env, args[0], &raw_public_key,
                                           &public_key_size),
                 "Unable to access ML-KEM public key")) {
    return nullptr;
  }
  if (public_key_size != lattice_wire::MlKem512::kPublicKeySize) {
    napi_throw_range_error(env, nullptr,
                           "ML-KEM-512 public key must be exactly 800 bytes");
    return nullptr;
  }

  bool use_secure_handle = false;
  if (argc == 2 &&
      !ParseSecureHandleOption(env, args[1], &use_secure_handle)) {
    return nullptr;
  }

  std::array<std::uint8_t, lattice_wire::MlKem512::kCiphertextSize> ciphertext{};
  const std::span<const std::uint8_t,
                   lattice_wire::MlKem512::kPublicKeySize>
      public_key(static_cast<const std::uint8_t*>(raw_public_key),
                 lattice_wire::MlKem512::kPublicKeySize);
  SharedSecretOutput shared_secret;
  if (!CreateSharedSecretOutput(env, use_secure_handle, &shared_secret)) {
    return nullptr;
  }
  const std::span<std::uint8_t, lattice_wire::MlKem512::kSharedSecretSize>
      shared_secret_span(shared_secret.data,
                         lattice_wire::MlKem512::kSharedSecretSize);
  if (!lattice_wire::MlKem512::Encapsulate(public_key, ciphertext,
                                           shared_secret_span)) {
    crypto_wipe(ciphertext.data(), ciphertext.size());
    ClearSharedSecretOutput(&shared_secret);
    napi_throw_error(env, nullptr, "ML-KEM-512 encapsulation failed");
    return nullptr;
  }

  napi_value result;
  napi_value ciphertext_buffer;
  void* copied_ciphertext = nullptr;
  const bool created =
      CheckNapi(env, napi_create_object(env, &result),
                "Unable to create ML-KEM encapsulation result") &&
      CheckNapi(env, napi_create_buffer_copy(
                         env, ciphertext.size(), ciphertext.data(),
                         &copied_ciphertext, &ciphertext_buffer),
                "Unable to copy ML-KEM ciphertext") &&
      CheckNapi(env, napi_set_named_property(env, result, "ciphertext",
                                             ciphertext_buffer),
                "Unable to set ML-KEM ciphertext") &&
      CheckNapi(env, napi_set_named_property(env, result, "sharedSecret",
                                             shared_secret.value),
                "Unable to set ML-KEM shared secret");
  crypto_wipe(ciphertext.data(), ciphertext.size());
  if (!created) {
    ClearSharedSecretOutput(&shared_secret);
  }
  return created ? result : nullptr;
}

napi_value DecapsulateMlKem512(napi_env env, napi_callback_info info) {
  std::size_t argc = 3;
  napi_value args[3];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc < 2 || argc > 3) {
    napi_throw_type_error(
        env, nullptr,
        "Expected a ciphertext Buffer, secret key, and optional secure-handle option");
    return nullptr;
  }

  bool is_ciphertext_buffer = false;
  if (!CheckNapi(env, napi_is_buffer(env, args[0], &is_ciphertext_buffer),
                 "Unable to inspect ML-KEM ciphertext")) {
    return nullptr;
  }
  if (!is_ciphertext_buffer) {
    napi_throw_type_error(env, nullptr,
                          "ML-KEM ciphertext must be a Node.js Buffer");
    return nullptr;
  }

  void* ciphertext_data = nullptr;
  std::size_t ciphertext_size = 0;
  if (!CheckNapi(env, napi_get_buffer_info(env, args[0], &ciphertext_data,
                                           &ciphertext_size),
                 "Unable to access ML-KEM ciphertext")) {
    return nullptr;
  }
  if (ciphertext_size != lattice_wire::MlKem512::kCiphertextSize) {
    napi_throw_range_error(env, nullptr,
                           "ML-KEM-512 ciphertext must be exactly 768 bytes");
    return nullptr;
  }

  const std::uint8_t* secret_key_data = nullptr;
  if (!GetSecretKeyData(env, args[1], lattice_wire::MlKem512::kSecretKeySize,
                        &secret_key_data)) {
    return nullptr;
  }

  bool use_secure_handle = false;
  if (argc == 3 &&
      !ParseSecureHandleOption(env, args[2], &use_secure_handle)) {
    return nullptr;
  }

  SharedSecretOutput shared_secret;
  if (!CreateSharedSecretOutput(env, use_secure_handle, &shared_secret)) {
    return nullptr;
  }
  const std::span<const std::uint8_t,
                  lattice_wire::MlKem512::kCiphertextSize>
      ciphertext(static_cast<const std::uint8_t*>(ciphertext_data),
                 lattice_wire::MlKem512::kCiphertextSize);
  const std::span<const std::uint8_t,
                  lattice_wire::MlKem512::kSecretKeySize>
      secret_key(secret_key_data, lattice_wire::MlKem512::kSecretKeySize);
  const std::span<std::uint8_t, lattice_wire::MlKem512::kSharedSecretSize>
      shared_secret_span(shared_secret.data,
                         lattice_wire::MlKem512::kSharedSecretSize);
  if (!lattice_wire::MlKem512::Decapsulate(ciphertext, secret_key,
                                           shared_secret_span)) {
    ClearSharedSecretOutput(&shared_secret);
    napi_throw_error(env, nullptr, "ML-KEM-512 decapsulation failed");
    return nullptr;
  }
  return shared_secret.value;
}

napi_value DeriveZeroRttKey(napi_env env, napi_callback_info info) {
  std::size_t argc = 3;
  napi_value args[3];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc < 2 || argc > 3) {
    napi_throw_type_error(
        env, nullptr,
        "Expected a shared secret, 812-byte header AAD, and optional secure-handle option");
    return nullptr;
  }

  const std::uint8_t* shared_secret_data = nullptr;
  if (!GetSecretKeyData(env, args[0],
                        lattice_wire::MlKem512::kSharedSecretSize,
                        &shared_secret_data)) {
    return nullptr;
  }

  bool is_header_buffer = false;
  if (!CheckNapi(env, napi_is_buffer(env, args[1], &is_header_buffer),
                 "Unable to inspect Zero-RTT header AAD")) {
    return nullptr;
  }
  if (!is_header_buffer) {
    napi_throw_type_error(env, nullptr,
                          "Zero-RTT header AAD must be a Node.js Buffer");
    return nullptr;
  }

  void* header_data = nullptr;
  std::size_t header_size = 0;
  if (!CheckNapi(env, napi_get_buffer_info(env, args[1], &header_data,
                                           &header_size),
                 "Unable to access Zero-RTT header AAD")) {
    return nullptr;
  }
  constexpr std::size_t kHeaderAadSize =
      lattice_wire::kHeaderSize + lattice_wire::kKemCiphertextSize +
      lattice_wire::kNonceSize;
  if (header_size != kHeaderAadSize) {
    napi_throw_range_error(env, nullptr,
                           "Zero-RTT header AAD must be exactly 812 bytes");
    return nullptr;
  }

  bool use_secure_handle = false;
  if (argc == 3 &&
      !ParseSecureHandleOption(env, args[2], &use_secure_handle)) {
    return nullptr;
  }
  SharedSecretOutput output;
  if (!CreateSharedSecretOutput(env, use_secure_handle, &output)) {
    return nullptr;
  }
  DeriveZeroRttAeadKey(
      shared_secret_data, static_cast<const std::uint8_t*>(header_data),
      output.data);
  return output.value;
}

napi_value SealZeroRttPayload(napi_env env, napi_callback_info info) {
  std::size_t argc = 3;
  napi_value args[3];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc != 3) {
    napi_throw_type_error(
        env, nullptr,
        "Expected a shared secret, 812-byte header AAD, and plaintext Buffer");
    return nullptr;
  }

  const std::uint8_t* shared_secret_data = nullptr;
  if (!GetSecretKeyData(env, args[0],
                        lattice_wire::MlKem512::kSharedSecretSize,
                        &shared_secret_data)) {
    return nullptr;
  }

  bool is_header_buffer = false;
  bool is_plaintext_buffer = false;
  if (!CheckNapi(env, napi_is_buffer(env, args[1], &is_header_buffer),
                 "Unable to inspect Zero-RTT header AAD") ||
      !CheckNapi(env, napi_is_buffer(env, args[2], &is_plaintext_buffer),
                 "Unable to inspect plaintext")) {
    return nullptr;
  }
  if (!is_header_buffer || !is_plaintext_buffer) {
    napi_throw_type_error(env, nullptr,
                          "Header AAD and plaintext must be Node.js Buffers");
    return nullptr;
  }

  void* header_data = nullptr;
  std::size_t header_size = 0;
  void* plaintext_data = nullptr;
  std::size_t plaintext_size = 0;
  if (!CheckNapi(env, napi_get_buffer_info(env, args[1], &header_data,
                                           &header_size),
                 "Unable to access Zero-RTT header AAD") ||
      !CheckNapi(env, napi_get_buffer_info(env, args[2], &plaintext_data,
                                           &plaintext_size),
                 "Unable to access plaintext")) {
    return nullptr;
  }
  constexpr std::size_t kHeaderAadSize =
      lattice_wire::kHeaderSize + lattice_wire::kKemCiphertextSize +
      lattice_wire::kNonceSize;
  if (header_size != kHeaderAadSize) {
    napi_throw_range_error(env, nullptr,
                           "Zero-RTT header AAD must be exactly 812 bytes");
    return nullptr;
  }
  if (plaintext_size > lattice_wire::kMaxPayloadSize) {
    napi_throw_range_error(env, nullptr,
                           "Zero-RTT plaintext exceeds the maximum payload size");
    return nullptr;
  }

  const std::size_t datagram_size =
      lattice_wire::kMinFrameSize + plaintext_size;
  napi_value datagram_buffer;
  void* datagram_data = nullptr;
  if (!CheckNapi(env, napi_create_buffer(env, datagram_size, &datagram_data,
                                        &datagram_buffer),
                 "Unable to allocate sealed Zero-RTT datagram")) {
    return nullptr;
  }
  auto* output = static_cast<std::uint8_t*>(datagram_data);
  const auto* header = static_cast<const std::uint8_t*>(header_data);
  std::memcpy(output, header, header_size);

  lattice_wire::FrameMetadata metadata{};
  if (lattice_wire::ValidateFrame(output, datagram_size, &metadata) !=
      lattice_wire::FrameError::kNone) {
    napi_throw_range_error(env, nullptr,
                           "Invalid Zero-RTT header or payload length");
    return nullptr;
  }

  std::array<std::uint8_t, lattice_wire::kAeadKeySize> aead_key{};
  DeriveZeroRttAeadKey(shared_secret_data, header, aead_key.data());
  const std::span<const std::uint8_t, lattice_wire::kAeadKeySize> key(
      aead_key.data(), aead_key.size());
  const std::span<const std::uint8_t, lattice_wire::kAeadNonceSize> nonce(
      header + lattice_wire::kHeaderSize +
          lattice_wire::kKemCiphertextSize,
      lattice_wire::kAeadNonceSize);
  const std::span<const std::uint8_t> associated_data(header, header_size);
  const auto* plaintext_bytes =
      static_cast<const std::uint8_t*>(plaintext_data);
  const std::span<const std::uint8_t> plaintext(plaintext_bytes,
                                                plaintext_size);
  std::span<std::uint8_t> ciphertext(
      output + kHeaderAadSize, plaintext_size);
  std::span<std::uint8_t, lattice_wire::kAeadTagSize> tag(
      output + kHeaderAadSize + plaintext_size,
      lattice_wire::kAeadTagSize);
  const bool encrypted = lattice_wire::AeadEncrypt(
      key, nonce, associated_data, plaintext, ciphertext, tag);
  crypto_wipe(aead_key.data(), aead_key.size());
  if (!encrypted) {
    napi_throw_error(env, nullptr, "Zero-RTT payload encryption failed");
    return nullptr;
  }
  return datagram_buffer;
}

napi_value AeadLock(napi_env env, napi_callback_info info) {
  std::size_t argc = 4;
  napi_value args[4];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc < 3 || argc > 4) {
    napi_throw_type_error(env, nullptr,
                          "Expected (key, nonce, plaintext[, aad])");
    return nullptr;
  }

  const std::uint8_t* key_data = nullptr;
  if (!GetSecretKeyData(env, args[0], lattice_wire::kAeadKeySize, &key_data)) {
    return nullptr;
  }

  void* nonce_data = nullptr;
  std::size_t nonce_size = 0;
  if (!GetBufferData(env, args[1], "Nonce must be a Node.js Buffer",
                     &nonce_data, &nonce_size)) {
    return nullptr;
  }
  if (nonce_size != lattice_wire::kAeadNonceSize) {
    napi_throw_range_error(env, nullptr, "Nonce must be exactly 12 bytes");
    return nullptr;
  }

  void* plaintext_data = nullptr;
  std::size_t plaintext_size = 0;
  if (!GetBufferData(env, args[2], "Plaintext must be a Node.js Buffer",
                     &plaintext_data, &plaintext_size)) {
    return nullptr;
  }
  if (plaintext_size > std::numeric_limits<std::size_t>::max() -
                           lattice_wire::kAeadTagSize) {
    napi_throw_range_error(env, nullptr, "Plaintext length is too large");
    return nullptr;
  }

  const std::uint8_t* aad_data = nullptr;
  std::size_t aad_size = 0;
  if (argc == 4 && !GetOptionalAad(env, args[3], &aad_data, &aad_size)) {
    return nullptr;
  }

  const std::size_t sealed_size =
      plaintext_size + lattice_wire::kAeadTagSize;
  napi_value sealed_buffer;
  void* sealed_data = nullptr;
  if (!CheckNapi(env, napi_create_buffer(env, sealed_size, &sealed_data,
                                        &sealed_buffer),
                 "Unable to allocate sealed AEAD Buffer")) {
    return nullptr;
  }

  auto* output = static_cast<std::uint8_t*>(sealed_data);
  const std::span<const std::uint8_t, lattice_wire::kAeadKeySize> key(
      key_data, lattice_wire::kAeadKeySize);
  const std::span<const std::uint8_t, lattice_wire::kAeadNonceSize> nonce(
      static_cast<const std::uint8_t*>(nonce_data),
      lattice_wire::kAeadNonceSize);
  const std::span<const std::uint8_t> associated_data(aad_data, aad_size);
  const std::span<const std::uint8_t> plaintext(
      static_cast<const std::uint8_t*>(plaintext_data), plaintext_size);
  const std::span<std::uint8_t> ciphertext(output, plaintext_size);
  const std::span<std::uint8_t, lattice_wire::kAeadTagSize> tag(
      output + plaintext_size, lattice_wire::kAeadTagSize);
  if (!lattice_wire::AeadEncrypt(key, nonce, associated_data, plaintext,
                                 ciphertext, tag)) {
    crypto_wipe(output, sealed_size);
    napi_throw_error(env, nullptr, "ChaCha20-Poly1305 encryption failed");
    return nullptr;
  }
  return sealed_buffer;
}

napi_value AeadUnlock(napi_env env, napi_callback_info info) {
  std::size_t argc = 4;
  napi_value args[4];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc < 3 || argc > 4) {
    napi_throw_type_error(env, nullptr,
                          "Expected (key, nonce, sealed[, aad])");
    return nullptr;
  }

  const std::uint8_t* key_data = nullptr;
  if (!GetSecretKeyData(env, args[0], lattice_wire::kAeadKeySize, &key_data)) {
    return nullptr;
  }

  void* nonce_data = nullptr;
  std::size_t nonce_size = 0;
  if (!GetBufferData(env, args[1], "Nonce must be a Node.js Buffer",
                     &nonce_data, &nonce_size)) {
    return nullptr;
  }
  if (nonce_size != lattice_wire::kAeadNonceSize) {
    napi_throw_range_error(env, nullptr, "Nonce must be exactly 12 bytes");
    return nullptr;
  }

  void* sealed_data = nullptr;
  std::size_t sealed_size = 0;
  if (!GetBufferData(env, args[2], "Sealed data must be a Node.js Buffer",
                     &sealed_data, &sealed_size)) {
    return nullptr;
  }
  if (sealed_size < lattice_wire::kAeadTagSize) {
    napi_throw_range_error(env, nullptr,
                           "Sealed data must include a 16-byte Poly1305 tag");
    return nullptr;
  }

  const std::uint8_t* aad_data = nullptr;
  std::size_t aad_size = 0;
  if (argc == 4 && !GetOptionalAad(env, args[3], &aad_data, &aad_size)) {
    return nullptr;
  }

  const std::size_t plaintext_size =
      sealed_size - lattice_wire::kAeadTagSize;
  napi_value plaintext_buffer;
  void* plaintext_data = nullptr;
  if (!CheckNapi(env, napi_create_buffer(env, plaintext_size, &plaintext_data,
                                        &plaintext_buffer),
                 "Unable to allocate decrypted plaintext Buffer")) {
    return nullptr;
  }

  const auto* sealed_bytes = static_cast<const std::uint8_t*>(sealed_data);
  const std::span<const std::uint8_t, lattice_wire::kAeadKeySize> key(
      key_data, lattice_wire::kAeadKeySize);
  const std::span<const std::uint8_t, lattice_wire::kAeadNonceSize> nonce(
      static_cast<const std::uint8_t*>(nonce_data),
      lattice_wire::kAeadNonceSize);
  const std::span<const std::uint8_t> associated_data(aad_data, aad_size);
  const std::span<const std::uint8_t> ciphertext(sealed_bytes, plaintext_size);
  const std::span<const std::uint8_t, lattice_wire::kAeadTagSize> tag(
      sealed_bytes + plaintext_size, lattice_wire::kAeadTagSize);
  const std::span<std::uint8_t> plaintext(
      static_cast<std::uint8_t*>(plaintext_data), plaintext_size);
  if (!lattice_wire::AeadDecrypt(key, nonce, associated_data, ciphertext, tag,
                                 plaintext)) {
    if (plaintext_data != nullptr && plaintext_size != 0) {
      crypto_wipe(plaintext_data, plaintext_size);
    }
    napi_throw_error(env, nullptr,
                     "ChaCha20-Poly1305 authentication failed");
    return nullptr;
  }
  return plaintext_buffer;
}

napi_value AeadUnlockInPlace(napi_env env, napi_callback_info info) {
  std::size_t argc = 4;
  napi_value args[4];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc < 3 || argc > 4) {
    napi_throw_type_error(env, nullptr,
                          "Expected (key, nonce, sealed[, aad])");
    return nullptr;
  }

  const std::uint8_t* key_data = nullptr;
  if (!GetSecretKeyData(env, args[0], lattice_wire::kAeadKeySize, &key_data)) {
    return nullptr;
  }

  void* nonce_data = nullptr;
  std::size_t nonce_size = 0;
  if (!GetBufferData(env, args[1], "Nonce must be a Node.js Buffer",
                     &nonce_data, &nonce_size)) {
    return nullptr;
  }
  if (nonce_size != lattice_wire::kAeadNonceSize) {
    napi_throw_range_error(env, nullptr, "Nonce must be exactly 12 bytes");
    return nullptr;
  }

  void* sealed_data = nullptr;
  std::size_t sealed_size = 0;
  if (!GetBufferData(env, args[2], "Sealed data must be a Node.js Buffer",
                     &sealed_data, &sealed_size)) {
    return nullptr;
  }
  if (sealed_size < lattice_wire::kAeadTagSize) {
    napi_throw_range_error(env, nullptr,
                           "Sealed data must include a 16-byte Poly1305 tag");
    return nullptr;
  }

  const std::uint8_t* aad_data = nullptr;
  std::size_t aad_size = 0;
  if (argc == 4 && !GetOptionalAad(env, args[3], &aad_data, &aad_size)) {
    return nullptr;
  }

  const std::size_t plaintext_size =
      sealed_size - lattice_wire::kAeadTagSize;
  auto* sealed_bytes = static_cast<std::uint8_t*>(sealed_data);
  auto* tag_bytes = sealed_bytes + plaintext_size;
  const std::span<const std::uint8_t, lattice_wire::kAeadKeySize> key(
      key_data, lattice_wire::kAeadKeySize);
  const std::span<const std::uint8_t, lattice_wire::kAeadNonceSize> nonce(
      static_cast<const std::uint8_t*>(nonce_data),
      lattice_wire::kAeadNonceSize);
  const std::span<const std::uint8_t> associated_data(aad_data, aad_size);
  const std::span<const std::uint8_t, lattice_wire::kAeadTagSize> tag(
      tag_bytes, lattice_wire::kAeadTagSize);
  const std::span<std::uint8_t> ciphertext_and_plaintext(sealed_bytes,
                                                         plaintext_size);
  if (!lattice_wire::AeadDecryptInPlace(
          key, nonce, associated_data, ciphertext_and_plaintext, tag)) {
    napi_throw_error(env, nullptr,
                     "ChaCha20-Poly1305 authentication failed");
    return nullptr;
  }
  crypto_wipe(tag_bytes, lattice_wire::kAeadTagSize);

  napi_value result;
  napi_value plaintext_length;
  if (!CheckNapi(env, napi_create_object(env, &result),
                 "Unable to create in-place decrypt result") ||
      !CheckNapi(env, napi_create_uint32(env,
                                         static_cast<std::uint32_t>(plaintext_size),
                                         &plaintext_length),
                 "Unable to create plaintext length") ||
      !CheckNapi(env, napi_set_named_property(env, result, "buffer", args[2]),
                 "Unable to set decrypted Buffer") ||
      !CheckNapi(env, napi_set_named_property(env, result, "plaintextLength",
                                              plaintext_length),
                 "Unable to set plaintext length")) {
    return nullptr;
  }
  return result;
}

napi_value CreateOneRttState(napi_env env, napi_callback_info info) {
  std::size_t argc = 2;
  napi_value args[2];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc < 1 || argc > 2) {
    napi_throw_type_error(env, nullptr,
                          "Expected (baseNonce[, initialTxSeq])");
    return nullptr;
  }

  void* nonce_data = nullptr;
  std::size_t nonce_size = 0;
  if (!GetBufferData(env, args[0], "Base nonce must be a 12-byte Buffer",
                     &nonce_data, &nonce_size)) {
    return nullptr;
  }
  if (nonce_size != lattice_wire::kAeadNonceSize) {
    napi_throw_range_error(env, nullptr, "Base nonce must be exactly 12 bytes");
    return nullptr;
  }

  std::uint64_t initial_sequence = 0;
  if (argc == 2) {
    napi_valuetype value_type;
    if (!CheckNapi(env, napi_typeof(env, args[1], &value_type),
                   "Unable to inspect initial sequence number")) {
      return nullptr;
    }
    if (value_type != napi_undefined && value_type != napi_null &&
        !GetUint64BigInt(env, args[1], &initial_sequence,
                         "initialTxSeq must be a valid uint64 BigInt")) {
      return nullptr;
    }
  }

  napi_value object;
  if (!CheckNapi(env, napi_create_object(env, &object),
                 "Unable to create 1-RTT state handle")) {
    return nullptr;
  }
  auto* handle = new (std::nothrow) OneRttStateHandle;
  if (handle == nullptr) {
    napi_throw_error(env, nullptr, "Unable to allocate 1-RTT state");
    return nullptr;
  }
  std::memcpy(handle->state.base_nonce, nonce_data,
              lattice_wire::kAeadNonceSize);
  handle->state.tx_sequence = initial_sequence;

  if (!CheckNapi(env, napi_wrap(env, object, handle, FinalizeOneRttState,
                                nullptr, nullptr),
                 "Unable to initialize 1-RTT state handle")) {
    delete handle;
    return nullptr;
  }
  if (!CheckNapi(env, napi_type_tag_object(env, object, &kOneRttStateTypeTag),
                 "Unable to tag 1-RTT state handle")) {
    return nullptr;
  }
  return object;
}

napi_value ResetOneRttReplayWindow(napi_env env, napi_callback_info info) {
  std::size_t argc = 1;
  napi_value args[1];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc != 1) {
    napi_throw_type_error(env, nullptr,
                          "Expected one 1-RTT state handle");
    return nullptr;
  }
  OneRttStateHandle* handle = nullptr;
  if (!GetOneRttState(env, args[0], &handle)) {
    return nullptr;
  }
  if (handle->destroyed) {
    napi_throw_error(env, nullptr, "1-RTT state has already been destroyed");
    return nullptr;
  }

  handle->state.rx_highest_sequence = 0;
  handle->state.rx_bitmap = 0;
  handle->state.rx_initialized = false;
  napi_value undefined;
  return CheckNapi(env, napi_get_undefined(env, &undefined),
                   "Unable to return replay reset status")
             ? undefined
             : nullptr;
}

napi_value DestroyOneRttState(napi_env env, napi_callback_info info) {
  std::size_t argc = 1;
  napi_value args[1];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc != 1) {
    napi_throw_type_error(env, nullptr,
                          "Expected one 1-RTT state handle");
    return nullptr;
  }
  OneRttStateHandle* handle = nullptr;
  if (!GetOneRttState(env, args[0], &handle)) {
    return nullptr;
  }
  if (!handle->destroyed) {
    crypto_wipe(&handle->state, sizeof(handle->state));
    handle->destroyed = true;
  }
  napi_value undefined;
  return CheckNapi(env, napi_get_undefined(env, &undefined),
                   "Unable to return state destruction status")
             ? undefined
             : nullptr;
}

napi_value SealOneRttFrame(napi_env env, napi_callback_info info) {
  std::size_t argc = 4;
  napi_value args[4];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc < 3 || argc > 4) {
    napi_throw_type_error(env, nullptr,
                          "Expected (key, state, plaintext[, aad])");
    return nullptr;
  }

  const std::uint8_t* key_data = nullptr;
  if (!GetSecretKeyData(env, args[0], lattice_wire::kAeadKeySize, &key_data)) {
    return nullptr;
  }
  OneRttStateHandle* handle = nullptr;
  if (!GetOneRttState(env, args[1], &handle)) {
    return nullptr;
  }
  if (handle->destroyed) {
    napi_throw_error(env, nullptr, "1-RTT state has already been destroyed");
    return nullptr;
  }
  if (handle->state.tx_exhausted) {
    napi_throw_range_error(env, nullptr,
                           "64-bit outbound sequence counter exhausted");
    return nullptr;
  }

  void* plaintext_data = nullptr;
  std::size_t plaintext_size = 0;
  if (!GetBufferData(env, args[2], "Plaintext must be a Node.js Buffer",
                     &plaintext_data, &plaintext_size)) {
    return nullptr;
  }
  if (plaintext_size > std::numeric_limits<std::size_t>::max() -
                           lattice_wire::kAeadTagSize) {
    napi_throw_range_error(env, nullptr, "Plaintext length is too large");
    return nullptr;
  }
  const std::uint8_t* aad_data = nullptr;
  std::size_t aad_size = 0;
  if (argc == 4 && !GetOptionalAad(env, args[3], &aad_data, &aad_size)) {
    return nullptr;
  }

  const std::size_t sealed_size =
      plaintext_size + lattice_wire::kAeadTagSize;
  napi_value sealed_buffer;
  void* sealed_data = nullptr;
  if (!CheckNapi(env, napi_create_buffer(env, sealed_size, &sealed_data,
                                        &sealed_buffer),
                 "Unable to allocate sealed 1-RTT Buffer")) {
    return nullptr;
  }

  const std::uint64_t sequence = handle->state.tx_sequence;
  auto* output = static_cast<std::uint8_t*>(sealed_data);
  napi_value sequence_value;
  napi_value result;
  if (!CheckNapi(env, napi_create_bigint_uint64(env, sequence, &sequence_value),
                 "Unable to create 1-RTT sequence number") ||
      !CheckNapi(env, napi_create_object(env, &result),
                 "Unable to create 1-RTT seal result") ||
      !CheckNapi(env, napi_set_named_property(env, result, "sequenceNumber",
                                               sequence_value),
                 "Unable to set 1-RTT sequence number") ||
      !CheckNapi(env, napi_set_named_property(env, result, "sealed",
                                               sealed_buffer),
                 "Unable to set sealed 1-RTT Buffer")) {
    crypto_wipe(output, sealed_size);
    return nullptr;
  }

  std::uint8_t nonce[lattice_wire::kAeadNonceSize];
  lattice_wire::BuildOneRttNonce(nonce, handle->state.base_nonce, sequence);
  const std::span<const std::uint8_t, lattice_wire::kAeadKeySize> key(
      key_data, lattice_wire::kAeadKeySize);
  const std::span<const std::uint8_t, lattice_wire::kAeadNonceSize> nonce_span(
      nonce, lattice_wire::kAeadNonceSize);
  const std::span<const std::uint8_t> associated_data(aad_data, aad_size);
  const std::span<const std::uint8_t> plaintext(
      static_cast<const std::uint8_t*>(plaintext_data), plaintext_size);
  const std::span<std::uint8_t> ciphertext(output, plaintext_size);
  const std::span<std::uint8_t, lattice_wire::kAeadTagSize> tag(
      output + plaintext_size, lattice_wire::kAeadTagSize);
  const bool encrypted = lattice_wire::AeadEncrypt(
      key, nonce_span, associated_data, plaintext, ciphertext, tag);
  crypto_wipe(nonce, sizeof(nonce));
  if (!encrypted) {
    crypto_wipe(output, sealed_size);
    napi_throw_error(env, nullptr, "1-RTT ChaCha20-Poly1305 encryption failed");
    return nullptr;
  }

  if (sequence == std::numeric_limits<std::uint64_t>::max()) {
    handle->state.tx_exhausted = true;
  } else {
    ++handle->state.tx_sequence;
  }
  return result;
}

napi_value OpenOneRttFrameImpl(napi_env env, napi_callback_info info,
                               bool in_place) {
  std::size_t argc = 5;
  napi_value args[5];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc < 4 || argc > 5) {
    napi_throw_type_error(
        env, nullptr,
        "Expected (key, state, sequenceNumber, sealed[, aad])");
    return nullptr;
  }

  const std::uint8_t* key_data = nullptr;
  if (!GetSecretKeyData(env, args[0], lattice_wire::kAeadKeySize, &key_data)) {
    return nullptr;
  }
  OneRttStateHandle* handle = nullptr;
  if (!GetOneRttState(env, args[1], &handle)) {
    return nullptr;
  }
  if (handle->destroyed) {
    napi_throw_error(env, nullptr, "1-RTT state has already been destroyed");
    return nullptr;
  }
  std::uint64_t sequence = 0;
  if (!GetUint64BigInt(env, args[2], &sequence,
                       "sequenceNumber must be a valid uint64 BigInt")) {
    return nullptr;
  }

  void* sealed_data = nullptr;
  std::size_t sealed_size = 0;
  if (!GetBufferData(env, args[3], "Sealed data must be a Node.js Buffer",
                     &sealed_data, &sealed_size)) {
    return nullptr;
  }
  if (sealed_size < lattice_wire::kAeadTagSize) {
    napi_throw_range_error(env, nullptr,
                           "Sealed data must include a 16-byte Poly1305 tag");
    return nullptr;
  }
  const std::uint8_t* aad_data = nullptr;
  std::size_t aad_size = 0;
  if (argc == 5 && !GetOptionalAad(env, args[4], &aad_data, &aad_size)) {
    return nullptr;
  }

  if (!lattice_wire::OneRttReplayInspect(handle->state, sequence)) {
    ThrowErrorWithCode(env, "ERR_REPLAY_DETECTED",
                       "Replay or stale sequence number rejected");
    return nullptr;
  }

  const std::size_t plaintext_size =
      sealed_size - lattice_wire::kAeadTagSize;
  if (in_place &&
      plaintext_size > std::numeric_limits<std::uint32_t>::max()) {
    napi_throw_range_error(env, nullptr,
                           "Plaintext is too large for the in-place result");
    return nullptr;
  }
  std::uint8_t nonce[lattice_wire::kAeadNonceSize];
  lattice_wire::BuildOneRttNonce(nonce, handle->state.base_nonce, sequence);
  const std::span<const std::uint8_t, lattice_wire::kAeadKeySize> key(
      key_data, lattice_wire::kAeadKeySize);
  const std::span<const std::uint8_t, lattice_wire::kAeadNonceSize> nonce_span(
      nonce, lattice_wire::kAeadNonceSize);
  const std::span<const std::uint8_t> associated_data(aad_data, aad_size);
  const auto* sealed_bytes = static_cast<const std::uint8_t*>(sealed_data);
  const std::span<const std::uint8_t, lattice_wire::kAeadTagSize> tag(
      sealed_bytes + plaintext_size, lattice_wire::kAeadTagSize);

  if (in_place) {
    auto* mutable_sealed = static_cast<std::uint8_t*>(sealed_data);
    const std::span<std::uint8_t> ciphertext_and_plaintext(
        mutable_sealed, plaintext_size);
    const bool authenticated = lattice_wire::AeadDecryptInPlace(
        key, nonce_span, associated_data, ciphertext_and_plaintext, tag);
    crypto_wipe(nonce, sizeof(nonce));
    if (!authenticated) {
      napi_throw_error(env, nullptr,
                       "ChaCha20-Poly1305 authentication failed");
      return nullptr;
    }
    if (!lattice_wire::OneRttReplayCommit(handle->state, sequence)) {
      crypto_wipe(mutable_sealed, sealed_size);
      ThrowErrorWithCode(env, "ERR_REPLAY_DETECTED",
                         "Replay commit failed");
      return nullptr;
    }
    crypto_wipe(mutable_sealed + plaintext_size,
                lattice_wire::kAeadTagSize);

    napi_value result;
    napi_value plaintext_length;
    if (!CheckNapi(env, napi_create_object(env, &result),
                   "Unable to create in-place open result") ||
        !CheckNapi(env, napi_create_uint32(
                            env, static_cast<std::uint32_t>(plaintext_size),
                            &plaintext_length),
                   "Unable to create plaintext length") ||
        !CheckNapi(env, napi_set_named_property(env, result, "buffer",
                                                 args[3]),
                   "Unable to set decrypted Buffer") ||
        !CheckNapi(env, napi_set_named_property(env, result,
                                                 "plaintextLength",
                                                 plaintext_length),
                   "Unable to set plaintext length")) {
      crypto_wipe(mutable_sealed, plaintext_size);
      return nullptr;
    }
    return result;
  }

  napi_value plaintext_buffer;
  void* plaintext_data = nullptr;
  if (!CheckNapi(env, napi_create_buffer(env, plaintext_size,
                                        &plaintext_data, &plaintext_buffer),
                 "Unable to allocate plaintext 1-RTT Buffer")) {
    crypto_wipe(nonce, sizeof(nonce));
    return nullptr;
  }
  const std::span<const std::uint8_t> ciphertext(sealed_bytes, plaintext_size);
  const std::span<std::uint8_t> plaintext(
      static_cast<std::uint8_t*>(plaintext_data), plaintext_size);
  const bool authenticated = lattice_wire::AeadDecrypt(
      key, nonce_span, associated_data, ciphertext, tag, plaintext);
  crypto_wipe(nonce, sizeof(nonce));
  if (!authenticated) {
    if (plaintext_data != nullptr && plaintext_size != 0) {
      crypto_wipe(plaintext_data, plaintext_size);
    }
    napi_throw_error(env, nullptr,
                     "ChaCha20-Poly1305 authentication failed");
    return nullptr;
  }
  if (!lattice_wire::OneRttReplayCommit(handle->state, sequence)) {
    if (plaintext_data != nullptr && plaintext_size != 0) {
      crypto_wipe(plaintext_data, plaintext_size);
    }
    ThrowErrorWithCode(env, "ERR_REPLAY_DETECTED",
                       "Replay commit failed");
    return nullptr;
  }
  return plaintext_buffer;
}

napi_value OpenOneRttFrame(napi_env env, napi_callback_info info) {
  return OpenOneRttFrameImpl(env, info, false);
}

napi_value OpenOneRttFrameInPlace(napi_env env, napi_callback_info info) {
  return OpenOneRttFrameImpl(env, info, true);
}

napi_value ProcessPacket(napi_env env, napi_callback_info info) {
  std::size_t argc = 1;
  napi_value args[1];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc != 1) {
    napi_throw_type_error(env, nullptr, "Expected one UDP Buffer argument");
    return nullptr;
  }

  bool is_buffer = false;
  if (!CheckNapi(env, napi_is_buffer(env, args[0], &is_buffer),
                 "Unable to inspect argument")) {
    return nullptr;
  }
  bool is_typed_array = false;
  if (!CheckNapi(env, napi_is_typedarray(env, args[0], &is_typed_array),
                 "Unable to inspect typed-array argument")) {
    return nullptr;
  }
  if (!is_buffer && !is_typed_array) {
    napi_throw_type_error(env, nullptr,
                          "Argument must be a Buffer or Uint8Array");
    return nullptr;
  }
  if (is_typed_array) {
    napi_typedarray_type type;
    std::size_t length = 0;
    void* data = nullptr;
    napi_value array_buffer;
    std::size_t offset = 0;
    if (!CheckNapi(env, napi_get_typedarray_info(env, args[0], &type, &length,
                                                 &data, &array_buffer, &offset),
                   "Unable to inspect typed-array data")) {
      return nullptr;
    }
    if (type != napi_uint8_array) {
      napi_throw_type_error(env, nullptr,
                            "Typed-array argument must use 8-bit elements");
      return nullptr;
    }
  }

  void* raw_data = nullptr;
  std::size_t size = 0;
  if (!CheckNapi(env, napi_get_buffer_info(env, args[0], &raw_data, &size),
                 "Unable to access Buffer data")) {
    return nullptr;
  }

  lattice_wire::FrameView view{};
  const auto error = lattice_wire::ParseFrame(
      static_cast<const std::uint8_t*>(raw_data), size, &view);
  if (error != lattice_wire::FrameError::kNone) {
    napi_throw_range_error(env, nullptr, ErrorMessage(error));
    return nullptr;
  }

  const auto& metadata = view.metadata;
  const auto* frame_data = static_cast<const std::uint8_t*>(raw_data);
  const auto payload_offset =
      static_cast<std::size_t>(view.encrypted_payload - frame_data);
  const auto tag_offset = static_cast<std::size_t>(view.tag - frame_data);
  napi_value result;
  napi_value stream_id;
  napi_value sequence_number;
  napi_value destination_key_id;
  napi_value payload_length;
  napi_value ciphertext_offset;
  napi_value nonce_offset;
  napi_value payload_offset_value;
  napi_value tag_offset_value;
  napi_value status;
  if (!CheckNapi(env, napi_create_object(env, &result),
                 "Unable to create result")) {
    return nullptr;
  }
  if (!CheckNapi(env, napi_create_uint32(env, metadata.stream_id, &stream_id),
                 "Unable to create stream ID")) {
    return nullptr;
  }
  if (!CheckNapi(env, napi_create_bigint_uint64(
                          env, metadata.sequence_number, &sequence_number),
                 "Unable to create sequence number")) {
    return nullptr;
  }
  if (!CheckNapi(env, napi_create_bigint_uint64(
                          env, metadata.destination_key_id, &destination_key_id),
                 "Unable to create destination key ID")) {
    return nullptr;
  }
  if (!CheckNapi(env, napi_create_uint32(env, metadata.payload_length,
                                         &payload_length),
                 "Unable to create payload length")) {
    return nullptr;
  }
  if (!CheckNapi(env, napi_create_uint32(env, lattice_wire::kHeaderSize,
                                         &ciphertext_offset),
                 "Unable to create ciphertext offset")) {
    return nullptr;
  }
  if (!CheckNapi(env, napi_create_uint32(
                          env, lattice_wire::kHeaderSize +
                                   lattice_wire::kKemCiphertextSize,
                          &nonce_offset),
                 "Unable to create nonce offset")) {
    return nullptr;
  }
  if (!CheckNapi(env, napi_create_uint32(env, payload_offset,
                                         &payload_offset_value),
                 "Unable to create payload offset")) {
    return nullptr;
  }
  if (!CheckNapi(env, napi_create_uint32(env, tag_offset, &tag_offset_value),
                 "Unable to create tag offset")) {
    return nullptr;
  }
  if (!CheckNapi(env, napi_create_string_utf8(
                          env, "FRAME_VALID_UNAUTHENTICATED",
                          NAPI_AUTO_LENGTH, &status),
                 "Unable to create status")) {
    return nullptr;
  }

  if (!CheckNapi(env, napi_set_named_property(env, result, "streamId", stream_id),
                 "Unable to set stream ID") ||
      !CheckNapi(env, napi_set_named_property(env, result, "sequenceNumber",
                                              sequence_number),
                 "Unable to set sequence number") ||
      !CheckNapi(env, napi_set_named_property(env, result, "destinationKeyId",
                                              destination_key_id),
                 "Unable to set destination key ID") ||
      !CheckNapi(env, napi_set_named_property(env, result, "payloadLength",
                                              payload_length),
                 "Unable to set payload length") ||
      !CheckNapi(env, napi_set_named_property(env, result,
                                              "ciphertextOffset",
                                              ciphertext_offset),
                 "Unable to set ciphertext offset") ||
      !CheckNapi(env, napi_set_named_property(env, result, "nonceOffset",
                                              nonce_offset),
                 "Unable to set nonce offset") ||
      !CheckNapi(env, napi_set_named_property(env, result, "payloadOffset",
                                              payload_offset_value),
                 "Unable to set payload offset") ||
      !CheckNapi(env, napi_set_named_property(env, result, "tagOffset",
                                              tag_offset_value),
                 "Unable to set tag offset") ||
      !CheckNapi(env, napi_set_named_property(env, result, "status", status),
                 "Unable to set status")) {
    return nullptr;
  }
  return result;
}

napi_value ProcessAuthenticatedPacket(napi_env env, napi_callback_info info) {
  std::size_t argc = 3;
  napi_value args[3];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc != 3) {
    napi_throw_type_error(env, nullptr,
                          "Expected a frame Buffer, 32-byte AEAD key, and replay window");
    return nullptr;
  }

  bool frame_is_buffer = false;
  bool key_is_buffer = false;
  if (!CheckNapi(env, napi_is_buffer(env, args[0], &frame_is_buffer),
                 "Unable to inspect frame argument") ||
      !CheckNapi(env, napi_is_buffer(env, args[1], &key_is_buffer),
                 "Unable to inspect AEAD key argument")) {
    return nullptr;
  }
  if (!frame_is_buffer || !key_is_buffer) {
    napi_throw_type_error(env, nullptr,
                          "Frame and AEAD key must be Node.js Buffers");
    return nullptr;
  }

  bool is_replay_window = false;
  if (!CheckNapi(env, napi_check_object_type_tag(
                          env, args[2], &kReplayWindowTypeTag,
                          &is_replay_window),
                 "Unable to inspect replay window")) {
    return nullptr;
  }
  if (!is_replay_window) {
    napi_throw_type_error(env, nullptr,
                          "Replay window must be created by createReplayWindow()");
    return nullptr;
  }
  ReplayWindowHandle* replay_window = nullptr;
  if (!CheckNapi(env, napi_unwrap(env, args[2],
                                  reinterpret_cast<void**>(&replay_window)),
                 "Unable to access replay window") ||
      replay_window == nullptr) {
    return nullptr;
  }

  void* raw_frame = nullptr;
  std::size_t frame_size = 0;
  void* raw_key = nullptr;
  std::size_t key_size = 0;
  if (!CheckNapi(env, napi_get_buffer_info(env, args[0], &raw_frame, &frame_size),
                 "Unable to access frame Buffer") ||
      !CheckNapi(env, napi_get_buffer_info(env, args[1], &raw_key, &key_size),
                 "Unable to access AEAD key Buffer")) {
    return nullptr;
  }
  if (key_size != lattice_wire::kAeadKeySize) {
    napi_throw_range_error(env, nullptr, "AEAD key must be exactly 32 bytes");
    return nullptr;
  }

  lattice_wire::FrameView view{};
  const auto* frame = static_cast<const std::uint8_t*>(raw_frame);
  const auto error = lattice_wire::ParseFrame(frame, frame_size, &view);
  if (error != lattice_wire::FrameError::kNone) {
    napi_throw_range_error(env, nullptr, ErrorMessage(error));
    return nullptr;
  }

  if (replay_window->window.Inspect(view.metadata.sequence_number) !=
      lattice_wire::ReplayStatus::kAcceptable) {
    napi_throw_range_error(env, nullptr, "Replay window rejected frame");
    return nullptr;
  }

  std::array<std::uint8_t, lattice_wire::kMaxPayloadSize> plaintext{};
  const auto plaintext_size =
      static_cast<std::size_t>(view.metadata.payload_length);
  const std::span<const std::uint8_t, lattice_wire::kAeadKeySize> key(
      static_cast<const std::uint8_t*>(raw_key),
      lattice_wire::kAeadKeySize);
  const std::span<const std::uint8_t, lattice_wire::kAeadNonceSize> nonce(
      view.nonce, lattice_wire::kAeadNonceSize);
  const std::span<const std::uint8_t> associated_data(
      view.header, lattice_wire::kHeaderSize +
                       lattice_wire::kKemCiphertextSize +
                       lattice_wire::kAeadNonceSize);
  const std::span<const std::uint8_t> ciphertext(view.encrypted_payload,
                                                  plaintext_size);
  const std::span<const std::uint8_t, lattice_wire::kAeadTagSize> tag(
      view.tag, lattice_wire::kAeadTagSize);
  const bool authenticated = lattice_wire::AeadDecrypt(
      key, nonce, associated_data, ciphertext, tag,
      std::span<std::uint8_t>(plaintext.data(), plaintext_size));
  if (!authenticated) {
    crypto_wipe(plaintext.data(), plaintext.size());
    napi_throw_error(env, nullptr, "Frame authentication failed");
    return nullptr;
  }
  if (!replay_window->window.CommitAfterAuthentication(
          view.metadata.sequence_number)) {
    crypto_wipe(plaintext.data(), plaintext.size());
    napi_throw_range_error(env, nullptr, "Replay window rejected frame");
    return nullptr;
  }

  napi_value result;
  napi_value plaintext_buffer;
  napi_value sequence_number;
  napi_value stream_id;
  napi_value status;
  void* copied_plaintext = nullptr;
  if (!CheckNapi(env, napi_create_object(env, &result),
                 "Unable to create result") ||
      !CheckNapi(env, napi_create_buffer_copy(
                          env, plaintext_size, plaintext.data(),
                          &copied_plaintext, &plaintext_buffer),
                 "Unable to copy authenticated plaintext") ||
      !CheckNapi(env, napi_create_bigint_uint64(
                          env, view.metadata.sequence_number, &sequence_number),
                 "Unable to create sequence number") ||
      !CheckNapi(env, napi_create_uint32(env, view.metadata.stream_id, &stream_id),
                 "Unable to create stream ID") ||
      !CheckNapi(env, napi_create_string_utf8(
                          env, "FRAME_AUTHENTICATED", NAPI_AUTO_LENGTH, &status),
                 "Unable to create status") ||
      !CheckNapi(env, napi_set_named_property(env, result, "plaintext",
                                              plaintext_buffer),
                 "Unable to set plaintext") ||
      !CheckNapi(env, napi_set_named_property(env, result, "sequenceNumber",
                                              sequence_number),
                 "Unable to set sequence number") ||
      !CheckNapi(env, napi_set_named_property(env, result, "streamId", stream_id),
                 "Unable to set stream ID") ||
      !CheckNapi(env, napi_set_named_property(env, result, "status", status),
                 "Unable to set status")) {
    crypto_wipe(plaintext.data(), plaintext.size());
    return nullptr;
  }
  crypto_wipe(plaintext.data(), plaintext.size());
  return result;
}

napi_value ProcessZeroRttDatagramImpl(napi_env env, napi_callback_info info,
                                      bool in_place) {
  std::size_t argc = 5;
  napi_value args[5];
  if (!CheckNapi(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr),
                 "Unable to read arguments")) {
    return nullptr;
  }
  if (argc != 4) {
    napi_throw_type_error(
        env, nullptr,
        "Expected a frame Buffer, 1632-byte ML-KEM secret key, destination key ID, and replay window");
    return nullptr;
  }

  bool frame_is_buffer = false;
  bool key_is_buffer = false;
  if (!CheckNapi(env, napi_is_buffer(env, args[0], &frame_is_buffer),
                 "Unable to inspect frame argument") ||
      !CheckNapi(env, napi_is_buffer(env, args[1], &key_is_buffer),
                 "Unable to inspect secret-key argument")) {
    return nullptr;
  }
  if (!frame_is_buffer) {
    napi_throw_type_error(env, nullptr,
                          "Frame must be a Node.js Buffer");
    return nullptr;
  }

  bool is_replay_window = false;
  if (!CheckNapi(env, napi_check_object_type_tag(
                          env, args[3], &kReplayWindowTypeTag,
                          &is_replay_window),
                 "Unable to inspect replay window")) {
    return nullptr;
  }
  if (!is_replay_window) {
    napi_throw_type_error(env, nullptr,
                          "Replay window must be created by createReplayWindow()");
    return nullptr;
  }
  ReplayWindowHandle* replay_window = nullptr;
  if (!CheckNapi(env, napi_unwrap(env, args[3],
                                  reinterpret_cast<void**>(&replay_window)),
                 "Unable to access replay window") ||
      replay_window == nullptr) {
    return nullptr;
  }

  napi_valuetype destination_id_type;
  if (!CheckNapi(env, napi_typeof(env, args[2], &destination_id_type),
                 "Unable to inspect destination key ID")) {
    return nullptr;
  }
  if (destination_id_type != napi_bigint) {
    napi_throw_type_error(env, nullptr,
                          "Destination key ID must be an unsigned 64-bit BigInt");
    return nullptr;
  }
  std::uint64_t destination_key_id = 0;
  bool lossless = false;
  if (!CheckNapi(env, napi_get_value_bigint_uint64(
                          env, args[2], &destination_key_id, &lossless),
                 "Unable to read destination key ID")) {
    return nullptr;
  }
  if (!lossless) {
    napi_throw_range_error(env, nullptr,
                           "Destination key ID must be an unsigned 64-bit BigInt");
    return nullptr;
  }

  void* raw_frame = nullptr;
  std::size_t frame_size = 0;
  const std::uint8_t* raw_key = nullptr;
  std::size_t key_size = 0;
  if (!CheckNapi(env, napi_get_buffer_info(env, args[0], &raw_frame, &frame_size),
                 "Unable to access frame Buffer")) {
    return nullptr;
  }
  if (key_is_buffer) {
    void* buffer_key = nullptr;
    if (!CheckNapi(env, napi_get_buffer_info(env, args[1], &buffer_key, &key_size),
                   "Unable to access ML-KEM secret-key Buffer")) {
      return nullptr;
    }
    raw_key = static_cast<const std::uint8_t*>(buffer_key);
  } else {
    napi_valuetype key_type;
    if (!CheckNapi(env, napi_typeof(env, args[1], &key_type),
                   "Unable to inspect ML-KEM secret-key handle")) {
      return nullptr;
    }
    if (key_type != napi_object) {
      napi_throw_type_error(
          env, nullptr,
          "ML-KEM secret key must be a Buffer or secure handle");
      return nullptr;
    }

    SecureSecretHandle* secure_secret = nullptr;
    if (!GetSecureSecretHandle(env, args[1], &secure_secret)) {
      return nullptr;
    }
    if (secure_secret->allocation.data == nullptr) {
      napi_throw_error(env, nullptr, "Secure secret has already been destroyed");
      return nullptr;
    }
    raw_key = secure_secret->allocation.data;
    key_size = secure_secret->allocation.requested_size;
  }
  if (key_size != lattice_wire::MlKem512::kSecretKeySize) {
    napi_throw_range_error(env, nullptr,
                           "ML-KEM-512 secret key must be exactly 1632 bytes");
    return nullptr;
  }

  std::array<std::uint8_t, lattice_wire::kMaxPayloadSize> plaintext{};
  const std::span<const std::uint8_t> datagram(
      static_cast<const std::uint8_t*>(raw_frame), frame_size);
  const std::span<std::uint8_t> mutable_datagram(
      static_cast<std::uint8_t*>(raw_frame), frame_size);
  const std::span<const std::uint8_t, lattice_wire::MlKem512::kSecretKeySize>
      secret_key(raw_key, key_size);
  const auto outcome =
      in_place
          ? lattice_wire::ProcessZeroRttDatagramInPlace(
                mutable_datagram, secret_key, destination_key_id,
                replay_window->window)
          : lattice_wire::ProcessZeroRttDatagram(
                datagram, secret_key, destination_key_id,
                replay_window->window, plaintext);
  if (outcome.status != lattice_wire::ZeroRttStatus::kAuthenticated) {
    crypto_wipe(plaintext.data(), plaintext.size());
    switch (outcome.status) {
      case lattice_wire::ZeroRttStatus::kInvalidFrame:
        napi_throw_range_error(env, nullptr, "Invalid lattice wire frame");
        break;
      case lattice_wire::ZeroRttStatus::kWrongDestination:
        napi_throw_error(env, nullptr, "Datagram addressed to another key ID");
        break;
      case lattice_wire::ZeroRttStatus::kReplayRejected:
      case lattice_wire::ZeroRttStatus::kReplayCommitFailed:
        napi_throw_range_error(env, nullptr, "Replay window rejected frame");
        break;
      case lattice_wire::ZeroRttStatus::kAuthenticationFailed:
        napi_throw_error(env, nullptr, "Frame authentication failed");
        break;
      case lattice_wire::ZeroRttStatus::kAuthenticated:
        break;
    }
    return nullptr;
  }

  napi_value result;
  napi_value plaintext_buffer;
  napi_value sequence_number;
  napi_value stream_id;
  napi_value status;
  void* copied_plaintext = nullptr;
  napi_value payload_offset;
  napi_value payload_length;
  if (!CheckNapi(env, napi_create_object(env, &result),
                 "Unable to create result") ||
      (!in_place &&
       !CheckNapi(env, napi_create_buffer_copy(
                           env, outcome.plaintext_size, plaintext.data(),
                           &copied_plaintext, &plaintext_buffer),
                  "Unable to copy authenticated plaintext")) ||
      (in_place &&
       (!CheckNapi(env, napi_create_uint32(
                           env, lattice_wire::kHeaderSize +
                                    lattice_wire::kKemCiphertextSize +
                                    lattice_wire::kNonceSize,
                           &payload_offset),
                   "Unable to create plaintext offset") ||
        !CheckNapi(env, napi_create_uint32(
                           env, outcome.plaintext_size, &payload_length),
                   "Unable to create plaintext length"))) ||
      !CheckNapi(env, napi_create_bigint_uint64(
                          env, outcome.sequence_number, &sequence_number),
                 "Unable to create sequence number") ||
      !CheckNapi(env, napi_create_uint32(env, outcome.stream_id, &stream_id),
                 "Unable to create stream ID") ||
      !CheckNapi(env, napi_create_string_utf8(
                          env, "FRAME_AUTHENTICATED", NAPI_AUTO_LENGTH, &status),
                 "Unable to create status")) {
    crypto_wipe(plaintext.data(), plaintext.size());
    return nullptr;
  }
  if (in_place) {
    if (!CheckNapi(env, napi_set_named_property(env, result, "frame", args[0]),
                   "Unable to set in-place frame") ||
        !CheckNapi(env, napi_set_named_property(env, result, "plaintextOffset",
                                                payload_offset),
                   "Unable to set plaintext offset") ||
        !CheckNapi(env, napi_set_named_property(env, result, "plaintextLength",
                                                payload_length),
                   "Unable to set plaintext length")) {
      return nullptr;
    }
  } else if (!CheckNapi(env, napi_set_named_property(env, result, "plaintext",
                                                     plaintext_buffer),
                        "Unable to set plaintext")) {
    crypto_wipe(plaintext.data(), plaintext.size());
    return nullptr;
  }
  if (!CheckNapi(env, napi_set_named_property(env, result, "sequenceNumber",
                                              sequence_number),
                 "Unable to set sequence number") ||
      !CheckNapi(env, napi_set_named_property(env, result, "streamId", stream_id),
                 "Unable to set stream ID") ||
      !CheckNapi(env, napi_set_named_property(env, result, "status", status),
                 "Unable to set status")) {
    crypto_wipe(plaintext.data(), plaintext.size());
    return nullptr;
  }
  crypto_wipe(plaintext.data(), plaintext.size());
  return result;
}

napi_value ProcessZeroRttDatagram(napi_env env, napi_callback_info info) {
  return ProcessZeroRttDatagramImpl(env, info, false);
}

napi_value ProcessZeroRttDatagramInPlace(napi_env env,
                                         napi_callback_info info) {
  return ProcessZeroRttDatagramImpl(env, info, true);
}

napi_value Init(napi_env env, napi_value exports) {
  napi_property_descriptor properties[] = {
      {"processPacket", nullptr, ProcessPacket, nullptr, nullptr, nullptr,
       napi_default, nullptr},
      {"processAuthenticatedPacket", nullptr, ProcessAuthenticatedPacket, nullptr,
       nullptr, nullptr, napi_default, nullptr},
      {"createReplayWindow", nullptr, CreateReplayWindow, nullptr, nullptr,
       nullptr, napi_default, nullptr},
      {"processZeroRttDatagram", nullptr, ProcessZeroRttDatagram, nullptr,
       nullptr, nullptr, napi_default, nullptr},
      {"processZeroRttDatagramInPlace", nullptr, ProcessZeroRttDatagramInPlace,
       nullptr, nullptr, nullptr, napi_default, nullptr},
      {"resetReplayWindow", nullptr, ResetReplayWindow, nullptr, nullptr,
       nullptr, napi_default, nullptr},
      {"generateMlKem512Keypair", nullptr, GenerateMlKem512Keypair, nullptr,
       nullptr, nullptr, napi_default, nullptr},
      {"encapsulateMlKem512", nullptr, EncapsulateMlKem512, nullptr, nullptr,
       nullptr, napi_default, nullptr},
      {"decapsulateMlKem512", nullptr, DecapsulateMlKem512, nullptr, nullptr,
       nullptr, napi_default, nullptr},
      {"allocateSecret", nullptr, AllocateSecret, nullptr, nullptr, nullptr,
       napi_default, nullptr},
      {"destroySecret", nullptr, DestroySecret, nullptr, nullptr, nullptr,
       napi_default, nullptr},
      {"deriveZeroRttKey", nullptr, DeriveZeroRttKey, nullptr, nullptr,
       nullptr, napi_default, nullptr},
      {"sealZeroRttPayload", nullptr, SealZeroRttPayload, nullptr, nullptr,
       nullptr, napi_default, nullptr},
      {"aeadLock", nullptr, AeadLock, nullptr, nullptr, nullptr, napi_default,
       nullptr},
      {"aeadUnlock", nullptr, AeadUnlock, nullptr, nullptr, nullptr,
       napi_default, nullptr},
      {"aeadUnlockInPlace", nullptr, AeadUnlockInPlace, nullptr, nullptr,
       nullptr, napi_default, nullptr},
      {"createOneRttState", nullptr, CreateOneRttState, nullptr, nullptr,
       nullptr, napi_default, nullptr},
      {"resetOneRttReplayWindow", nullptr, ResetOneRttReplayWindow, nullptr,
       nullptr, nullptr, napi_default, nullptr},
      {"sealOneRttFrame", nullptr, SealOneRttFrame, nullptr, nullptr, nullptr,
       napi_default, nullptr},
      {"openOneRttFrame", nullptr, OpenOneRttFrame, nullptr, nullptr, nullptr,
       napi_default, nullptr},
      {"openOneRttFrameInPlace", nullptr, OpenOneRttFrameInPlace, nullptr,
       nullptr, nullptr, napi_default, nullptr},
      {"destroyOneRttState", nullptr, DestroyOneRttState, nullptr, nullptr,
       nullptr, napi_default, nullptr},
  };
  if (!CheckNapi(env, napi_define_properties(env, exports, 22, properties),
                 "Unable to initialize native addon")) {
    return nullptr;
  }
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
