#include <auth/infra/mapping/dto_mappers.hpp>

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
        dto.is_email_verified = user.is_email_verified;
        dto.is_phone_verified = user.is_phone_verified;

        return dto;
    }
}
