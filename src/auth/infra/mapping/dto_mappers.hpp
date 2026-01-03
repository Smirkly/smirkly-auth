#pragma once

#include <auth/api/v0/dto/sign_up_request.hpp>
#include <auth/api/v0/dto/tokens_response.hpp>
#include <auth/api/v0/dto/user_response.hpp>
#include <auth/services/contracts/sign_in.hpp>
#include <auth/services/contracts/sign_up.hpp>

namespace smirkly::auth::infra::mapping {
    services::SignUpCommand ToDomain(const api::v0::dto::SignUpRequest &dto);

    api::v0::dto::TokensResponse ToTokensDto(const services::SignInResult &result);

    api::v0::dto::UserResponse ToUserDto(const domain::models::User &user);
}
