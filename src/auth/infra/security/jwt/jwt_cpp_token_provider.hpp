#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <string_view>

#include <auth/services/contracts/auth_tokens.hpp>
#include <auth/services/ports/security/jwt_token_provider.hpp>

namespace smirkly::auth::infra::security::jwt {
struct JwtConfig {
  std::string private_key_pem;
  std::string public_key_pem;
  std::string key_id;
  std::string issuer;
  std::string audience;
  std::chrono::seconds access_ttl;
  std::chrono::seconds refresh_ttl;
};

class JwtCppTokenProvider final
    : public services::ports::security::JwtTokenProvider {
 public:
  explicit JwtCppTokenProvider(JwtConfig config);

  [[nodiscard]] services::contracts::AuthTokens GenerateTokens(
      std::string_view user_id, std::string_view session_id,
      std::string_view token_family_id) const override;

  [[nodiscard]] std::string GenerateAccessToken(
      std::string_view user_id, std::string_view session_id) const override;

  [[nodiscard]] std::string GenerateRefreshToken(
      std::string_view user_id, std::string_view session_id,
      std::string_view token_family_id) const override;

  [[nodiscard]] services::ports::security::RefreshTokenClaims ParseRefreshToken(
      std::string_view refresh_token) const override;

  [[nodiscard]] const std::string& GetPublicJwksJson() const noexcept;

 private:
  [[nodiscard]] std::string GenerateToken(
      std::string_view user_id, std::string_view session_id,
      const std::optional<std::string>& token_family_id,
      std::string_view token_type, std::chrono::seconds ttl) const;

 private:
  JwtConfig config_;
  std::string public_jwks_json_;
};
}  // namespace smirkly::auth::infra::security::jwt
