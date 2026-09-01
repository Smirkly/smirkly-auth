#pragma once

#include <string>

#include <auth/services/ports/security/token_hasher.hpp>

namespace smirkly::auth::infra::security {
class HmacSha256TokenHasher final
    : public services::ports::security::TokenHasher {
 public:
  explicit HmacSha256TokenHasher(std::string pepper);

  [[nodiscard]] std::string Hash(std::string_view token) const override;

  [[nodiscard]] bool Verify(std::string_view token,
                            std::string_view hash) const override;

 private:
  std::string pepper_;
};
}  // namespace smirkly::auth::infra::security
