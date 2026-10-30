#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include <auth/services/ports/security/password_hasher.hpp>

namespace smirkly::auth::infra::security {

struct Argon2idParams final {
  std::uint32_t time_cost{2};
  std::uint32_t memory_cost_kib{19 * 1024};
  std::uint32_t parallelism{1};
  std::uint32_t salt_length{16};
  std::uint32_t hash_length{32};
};

class Argon2idPasswordHasher final : public services::ports::PasswordHasher {
 public:
  explicit Argon2idPasswordHasher(Argon2idParams params = {});

  [[nodiscard]] std::string Hash(std::string_view password) const override;

  [[nodiscard]] bool Verify(std::string_view password,
                            std::string_view encoded_hash) const override;

 private:
  Argon2idParams params_;
};

}  // namespace smirkly::auth::infra::security
