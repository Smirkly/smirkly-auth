#include <auth/api/v0/handlers/change_password_handler.hpp>

#include <chrono>

#include <userver/components/component_context.hpp>
#include <userver/server/http/http_response_cookie.hpp>
#include <userver/server/http/http_status.hpp>

#include <auth/api/v0/auth/bearer_token.hpp>
#include <auth/api/v0/utils/auth_error_mapper.hpp>
#include <auth/api/v0/utils/json_error.hpp>
#include <auth/components/auth_application_component.hpp>
#include <auth/services/contracts/change_password.hpp>
#include <auth/services/usecases/authentication_service.hpp>
#include <auth/services/usecases/password_service.hpp>

namespace {
void ClearRefreshCookie(const userver::server::http::HttpRequest& request) {
  request.GetHttpResponse().SetCookie(
      userver::server::http::Cookie("refresh_token", "")
          .SetHttpOnly()
          .SetSecure()
          .SetPath("/auth/v0/refresh")
          .SetSameSite("Strict")
          .SetMaxAge(std::chrono::seconds{0}));
}
}  // namespace

namespace smirkly::auth::api::v0::handlers {
ChangePasswordHandler::ChangePasswordHandler(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context)
    : HttpHandlerJsonBase(config, context),
      authentication_service_(
          context.FindComponent<components::AuthApplicationComponent>()
              .GetAuthenticationService()),
      password_service_(
          context.FindComponent<components::AuthApplicationComponent>()
              .GetPasswordService()) {}

ChangePasswordHandler::Value ChangePasswordHandler::HandleRequestJsonThrow(
    const HttpRequest& request, const Value& body, RequestContext&) const {
  const auto access_token = auth::ExtractBearerToken(request);
  if (!access_token) {
    request.GetHttpResponse().SetStatus(
        userver::server::http::HttpStatus::kUnauthorized);
    return utils::ErrorResponse("auth.missing_access_token",
                                "missing access token");
  }

  if (!body.HasMember("current_password") || !body.HasMember("new_password")) {
    request.GetHttpResponse().SetStatus(
        userver::server::http::HttpStatus::kBadRequest);
    return utils::ErrorResponse(
        "auth.change_password.validation_failed",
        "current_password and new_password are required");
  }

  const services::contracts::ChangePasswordCommand cmd{
      .current_password = body["current_password"].As<std::string>(),
      .new_password = body["new_password"].As<std::string>(),
  };

  try {
    const auto context =
        authentication_service_.AuthenticateAccessToken(*access_token);
    password_service_.ChangePassword(context, cmd);
    ClearRefreshCookie(request);

    request.GetHttpResponse().SetStatus(
        userver::server::http::HttpStatus::kNoContent);
    return {};
  } catch (const std::exception& e) {
    return utils::AuthErrorResponse(request, e);
  }
}
}  // namespace smirkly::auth::api::v0::handlers
