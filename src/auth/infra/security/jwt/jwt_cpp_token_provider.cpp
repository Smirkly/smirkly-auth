#include <auth/infra/security/jwt/jwt_cpp_token_provider.hpp>

#include <chrono>
#include <optional>
#include <string>
#include <utility>

#include <jwt/jwt.hpp>

namespace smirkly::auth::infra::security::jwt {
    namespace {
        std::chrono::system_clock::time_point Now() {
            return std::chrono::system_clock::now();
        }
    }

    JwtCppTokenProvider::JwtCppTokenProvider(JwtConfig config)
        : config_(std::move(config)) {
    }

    services::contracts::AuthTokens JwtCppTokenProvider::GenerateTokens(
        std::string_view user_id,
        std::string_view session_id,
        std::string_view token_family_id
    ) const {
        return {
            .access_token = GenerateAccessToken(user_id, session_id),
            .refresh_token = GenerateRefreshToken(user_id, session_id, token_family_id),
        };
    }

    std::string JwtCppTokenProvider::GenerateAccessToken(
        std::string_view user_id,
        std::string_view session_id
    ) const {
        return GenerateToken(
            user_id,
            session_id,
            std::nullopt,
            "access",
            config_.access_ttl
        );
    }

    std::string JwtCppTokenProvider::GenerateRefreshToken(
        std::string_view user_id,
        std::string_view session_id,
        std::string_view token_family_id
    ) const {
        return GenerateToken(
            user_id,
            session_id,
            std::string(token_family_id),
            "refresh",
            config_.refresh_ttl
        );
    }

    std::string JwtCppTokenProvider::GenerateToken(
        std::string_view user_id,
        std::string_view session_id,
        const std::optional<std::string> &token_family_id,
        std::string_view token_type,
        std::chrono::seconds ttl
    ) const {
        const auto now = Now();

        ::jwt::jwt_object obj{
            ::jwt::params::algorithm("HS256"),
            ::jwt::params::secret(config_.secret),
            ::jwt::params::payload({
                {"sub", std::string(user_id)},
                {"sid", std::string(session_id)},
                {"type", std::string(token_type)},
            })
        };

        if (token_family_id) {
            obj.add_claim("fam", *token_family_id);
        }

        obj.add_claim("iss", config_.issuer)
                .add_claim("iat", now)
                .add_claim("exp", now + ttl);

        return obj.signature();
    }
}
