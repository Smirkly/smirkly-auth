#include <auth/infra/security/password/argon2id_password_hasher.hpp>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <argon2.h>
#include <openssl/rand.h>

namespace smirkly::auth::infra::security {
namespace {

constexpr std::uint32_t kMinSaltLength = 8;
constexpr std::uint32_t kMinHashLength = 4;
constexpr std::uint32_t kMaxSaltLength = 1024;
constexpr std::uint32_t kMaxHashLength = 1024;

void ValidateParams(const Argon2idParams& params) {
  if (params.time_cost == 0) {
    throw std::invalid_argument("Argon2id time cost must be positive");
  }
  if (params.parallelism == 0) {
    throw std::invalid_argument("Argon2id parallelism must be positive");
  }
  if (static_cast<std::uint64_t>(params.memory_cost_kib) <
      8ULL * params.parallelism) {
    throw std::invalid_argument(
        "Argon2id memory cost must be at least 8 KiB per lane");
  }
  if (params.salt_length < kMinSaltLength) {
    throw std::invalid_argument("Argon2id salt is too short");
  }
  if (params.salt_length > kMaxSaltLength) {
    throw std::invalid_argument("Argon2id salt is too long");
  }
  if (params.hash_length < kMinHashLength) {
    throw std::invalid_argument("Argon2id hash is too short");
  }
  if (params.hash_length > kMaxHashLength) {
    throw std::invalid_argument("Argon2id hash is too long");
  }
}

[[noreturn]] void ThrowArgon2Error(std::string_view operation, int error_code) {
  throw std::runtime_error(std::string{operation} + ": " +
                           argon2_error_message(error_code));
}

const void* PasswordData(std::string_view password) noexcept {
  static constexpr char kEmptyPassword = '\0';
  return password.empty() ? &kEmptyPassword : password.data();
}

}  // namespace

Argon2idPasswordHasher::Argon2idPasswordHasher(Argon2idParams params)
    : params_(params) {
  ValidateParams(params_);
}

std::string Argon2idPasswordHasher::Hash(std::string_view password) const {
  std::vector<unsigned char> salt(params_.salt_length);
  if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
    throw std::runtime_error("failed to generate Argon2id salt");
  }

  const auto encoded_length = argon2_encodedlen(
      params_.time_cost, params_.memory_cost_kib, params_.parallelism,
      params_.salt_length, params_.hash_length, Argon2_id);
  std::vector<char> encoded(encoded_length);

  const auto result = argon2id_hash_encoded(
      params_.time_cost, params_.memory_cost_kib, params_.parallelism,
      PasswordData(password), password.size(), salt.data(), salt.size(),
      params_.hash_length, encoded.data(), encoded.size());
  if (result != ARGON2_OK) {
    ThrowArgon2Error("failed to hash password with Argon2id", result);
  }

  return std::string{encoded.data()};
}

bool Argon2idPasswordHasher::Verify(std::string_view password,
                                    std::string_view encoded_hash) const {
  if (encoded_hash.empty()) {
    return false;
  }

  const std::string null_terminated_hash{encoded_hash};
  const auto result = argon2id_verify(null_terminated_hash.c_str(),
                                      PasswordData(password), password.size());
  if (result == ARGON2_OK) {
    return true;
  }
  if (result == ARGON2_MEMORY_ALLOCATION_ERROR ||
      result == ARGON2_THREAD_FAIL) {
    ThrowArgon2Error("failed to verify Argon2id password", result);
  }
  return false;
}

}  // namespace smirkly::auth::infra::security
