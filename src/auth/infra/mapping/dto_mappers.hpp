#pragma once

#include <auth/api/v0/dto/sign_up_request.hpp>
#include <auth/api/v0/dto/tokens_response.hpp>
#include <auth/api/v0/dto/user_response.hpp>
#include <auth/domain/services/auth_service_types.hpp>

namespace smirkly::auth::infra::mapping {
    domain::SignUpCommand ToDomain(const api::v0::dto::SignUpRequest &dto);

    api::v0::dto::TokensResponse ToTokensDto(const domain::AuthResult &result);

    api::v0::dto::UserResponse ToUserDto(const domain::models::User &user);
}
