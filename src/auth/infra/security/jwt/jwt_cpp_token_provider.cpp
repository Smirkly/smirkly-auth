#include <auth/infra/security/jwt/jwt_cpp_token_provider.hpp>

#include <chrono>
#include <optional>
#include <string>
#include <utility>

#include <jwt/jwt.hpp>

#include <auth/services/errors/refresh_errors.hpp>

namespace smirkly::auth::infra::security::jwt {
    namespace {
        constexpr std::string_view kAccessTokenType = "access";
        constexpr std::string_view kRefreshTokenType = "refresh";
        constexpr std::string_view kIssuerClaim = "iss";
        constexpr std::string_view kSubjectClaim = "sub";
        constexpr std::string_view kSessionIdClaim = "sid";
        constexpr std::string_view kTokenTypeClaim = "type";
        constexpr std::string_view kTokenFamilyClaim = "fam";

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
            kAccessTokenType,
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
            kRefreshTokenType,
            config_.refresh_ttl
        );
    }

    services::ports::security::RefreshTokenClaims JwtCppTokenProvider::ParseRefreshToken(
        std::string_view refresh_token
    ) const {
        try {
            auto decoded = ::jwt::decode(
                std::string(refresh_token),
                ::jwt::params::algorithms({"HS256"}),
                ::jwt::params::secret(config_.secret),
                ::jwt::params::verify(true)
            );

            const auto issuer = decoded.payload().get_claim_value<std::string>(std::string{kIssuerClaim});
            if (issuer != config_.issuer) {
                throw services::errors::InvalidRefreshToken("invalid refresh token");
            }

            const auto token_type = decoded.payload().get_claim_value<std::string>(std::string{kTokenTypeClaim});
            if (token_type != kRefreshTokenType) {
                throw services::errors::InvalidRefreshToken("invalid refresh token");
            }

            services::ports::security::RefreshTokenClaims claims{
                .user_id = decoded.payload().get_claim_value<std::string>(std::string{kSubjectClaim}),
                .session_id = decoded.payload().get_claim_value<std::string>(std::string{kSessionIdClaim}),
                .token_family_id = std::nullopt,
            };

            try {
                claims.token_family_id =
                        decoded.payload().get_claim_value<std::string>(std::string{kTokenFamilyClaim});
            } catch (const std::exception &) {
            }

            return claims;
        } catch (const services::errors::InvalidRefreshToken &) {
            throw;
        } catch (const std::exception &) {
            throw services::errors::InvalidRefreshToken("invalid refresh token");
        }
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
