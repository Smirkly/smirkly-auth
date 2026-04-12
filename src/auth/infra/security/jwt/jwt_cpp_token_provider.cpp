#include <auth/infra/security/jwt/jwt_cpp_token_provider.hpp>

#include <chrono>
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

    services::contracts::AuthTokens JwtCppTokenProvider::GenerateTokens(std::string_view user_id) const {
        return {
            .access_token = GenerateAccessToken(user_id),
            .refresh_token = GenerateRefreshToken(user_id),
        };
    }

    std::string JwtCppTokenProvider::GenerateAccessToken(std::string_view user_id) const {
        return GenerateToken(user_id, "access", config_.access_ttl);
    }

    std::string JwtCppTokenProvider::GenerateRefreshToken(std::string_view user_id) const {
        return GenerateToken(user_id, "refresh", config_.refresh_ttl);
    }

    std::string JwtCppTokenProvider::GenerateToken(
        std::string_view user_id,
        std::string_view token_type,
        std::chrono::seconds ttl
    ) const {
        ::jwt::jwt_object obj{
            ::jwt::params::algorithm("HS256"),
            ::jwt::params::secret(config_.secret),
            ::jwt::params::payload({
                {"sub", std::string(user_id)},
                {"type", std::string(token_type)},
            })
        };

        obj.add_claim("iss", config_.issuer)
                .add_claim("iat", Now())
                .add_claim("exp", Now() + ttl);

        return obj.signature();
    }
}
