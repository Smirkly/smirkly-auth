#include <auth/infra/mapping/dto_mappers.hpp>

namespace smirkly::auth::infra::mapping {
    services::SignUpCommand ToDomain(const api::v0::dto::SignUpRequest &dto) {
        services::SignUpCommand cmd;
        cmd.username = dto.username;
        cmd.password = dto.password;
        cmd.phone = dto.phone;
        cmd.email = dto.email;
        return cmd;
    }

    api::v0::dto::TokensResponse ToTokensDto(const services::SignInResult &result) {
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
