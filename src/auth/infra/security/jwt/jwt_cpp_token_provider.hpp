#pragma once

#include <chrono>
#include <string>
#include <string_view>

#include <auth/services/contracts/auth_tokens.hpp>
#include <auth/services/ports/security/jwt_token_provider.hpp>

namespace smirkly::auth::infra::security::jwt {
    struct JwtConfig {
        std::string secret;
        std::string issuer;
        std::chrono::seconds access_ttl;
        std::chrono::seconds refresh_ttl;
    };

    class JwtCppTokenProvider final : public services::ports::security::JwtTokenProvider {
    public:
        explicit JwtCppTokenProvider(JwtConfig config);

        [[nodiscard]] services::contracts::AuthTokens GenerateTokens(std::string_view user_id) const override;

        [[nodiscard]] std::string GenerateAccessToken(std::string_view user_id) const override;

        [[nodiscard]] std::string GenerateRefreshToken(std::string_view user_id) const override;

    private:
        [[nodiscard]] std::string GenerateToken(
            std::string_view user_id,
            std::string_view token_type,
            std::chrono::seconds ttl
        ) const;

    private:
        JwtConfig config_;
    };
}
