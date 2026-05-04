#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <auth/services/contracts/auth_tokens.hpp>

namespace smirkly::auth::services::ports::security {
struct RefreshTokenClaims final {
  std::string user_id;
  std::string session_id;
  std::optional<std::string> token_family_id;
};

class JwtTokenProvider {
 public:
  virtual ~JwtTokenProvider() = default;

  [[nodiscard]] virtual contracts::AuthTokens GenerateTokens(
      std::string_view user_id, std::string_view session_id,
      std::string_view token_family_id) const = 0;

  [[nodiscard]] virtual std::string GenerateAccessToken(
      std::string_view user_id, std::string_view session_id) const = 0;

  [[nodiscard]] virtual std::string GenerateRefreshToken(
      std::string_view user_id, std::string_view session_id,
      std::string_view token_family_id) const = 0;

  [[nodiscard]] virtual RefreshTokenClaims ParseRefreshToken(
      std::string_view refresh_token) const = 0;
};
}  // namespace smirkly::auth::services::ports::security
