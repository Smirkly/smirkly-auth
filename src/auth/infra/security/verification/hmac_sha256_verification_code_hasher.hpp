#pragma once

#include <string>
#include <string_view>

#include <auth/infra/security/token/hmac_sha256_token_hasher.hpp>
#include <auth/services/ports/security/verification_code_hasher.hpp>

namespace smirkly::auth::infra::security {

class HmacSha256VerificationCodeHasher final
    : public services::ports::security::VerificationCodeHasher {
 public:
  explicit HmacSha256VerificationCodeHasher(std::string pepper);

  [[nodiscard]] std::string Hash(std::string_view user_id,
                                 std::string_view code) const override;

  [[nodiscard]] bool Verify(std::string_view user_id, std::string_view code,
                            std::string_view hash) const override;

 private:
  [[nodiscard]] static std::string BuildScopedValue(std::string_view user_id,
                                                    std::string_view code);

  HmacSha256TokenHasher hmac_;
};

}  // namespace smirkly::auth::infra::security
