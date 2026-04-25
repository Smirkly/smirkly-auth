#include <auth/infra/mapping/dto_mappers.hpp>

namespace {
    std::optional<std::string> ExtractIp(const userver::server::http::HttpRequest &request) {
        if (const auto xff = request.GetHeader("X-Forwarded-For"); !xff.empty()) {
            return std::string{xff};
        }
        if (const auto xri = request.GetHeader("X-Real-IP"); !xri.empty()) {
            return std::string{xri};
        }
        return std::nullopt;
    }

    std::optional<std::string> ExtractHeader(
        const userver::server::http::HttpRequest &request,
        std::string_view name
    ) {
        const auto value = request.GetHeader(name);
        if (value.empty()) {
            return std::nullopt;
        }
        return std::string{value};
    }
}

namespace smirkly::auth::infra::mapping {
    services::contracts::SignUpCommand ToDomain(const api::v0::dto::SignUpRequest &dto) {
        services::contracts::SignUpCommand cmd;
        cmd.username = dto.username;
        cmd.password = dto.password;
        cmd.phone = dto.phone;
        cmd.email = dto.email;
        return cmd;
    }

    services::contracts::SignInCommand ToDomain(const api::v0::dto::SignInRequest &dto) {
        services::contracts::SignInCommand cmd;
        cmd.username = dto.username;
        cmd.email = dto.email;
        cmd.phone = dto.phone;
        cmd.password = dto.password;
        return cmd;
    }

    services::contracts::RequestMeta ToRequestMeta(const userver::server::http::HttpRequest &request) {
        services::contracts::RequestMeta meta;
        meta.ip = ExtractIp(request);
        meta.user_agent = ExtractHeader(request, "User-Agent");
        return meta;
    }

    api::v0::dto::TokensResponse ToTokensDto(const services::contracts::SignInResult &result) {
        api::v0::dto::TokensResponse dto;
        const auto &tokens = result.tokens;
        dto.access_token = tokens.access_token;
        dto.refresh_token = tokens.refresh_token;
        return dto;
    }

    api::v0::dto::UserResponse ToUserDto(const domain::models::User &user) {
        api::v0::dto::UserResponse dto;
        dto.id = user.id;
        dto.username = user.username;
        dto.phone = user.phone;
        dto.email = user.email;

        return dto;
    }
}
