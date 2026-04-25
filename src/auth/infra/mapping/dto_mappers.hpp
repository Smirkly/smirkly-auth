#pragma once

#include <userver/server/http/http_request.hpp>

#include <auth/api/v0/dto/sign_in_request.hpp>
#include <auth/api/v0/dto/sign_up_request.hpp>
#include <auth/api/v0/dto/tokens_response.hpp>
#include <auth/api/v0/dto/user_response.hpp>
#include <auth/services/contracts/request_meta.hpp>
#include <auth/services/contracts/sign_in.hpp>
#include <auth/services/contracts/sign_up.hpp>

namespace smirkly::auth::infra::mapping {
    services::contracts::SignUpCommand ToDomain(const api::v0::dto::SignUpRequest &dto);

    services::contracts::SignInCommand ToDomain(const api::v0::dto::SignInRequest &dto);

    services::contracts::RequestMeta ToRequestMeta(const userver::server::http::HttpRequest &request);

    api::v0::dto::TokensResponse ToTokensDto(const services::contracts::SignInResult &result);

    api::v0::dto::UserResponse ToUserDto(const domain::models::User &user);
}
