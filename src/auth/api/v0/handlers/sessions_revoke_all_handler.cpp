#include <auth/api/v0/handlers/sessions_revoke_all_handler.hpp>

#include <chrono>

#include <userver/components/component_context.hpp>
#include <userver/server/http/http_response_cookie.hpp>
#include <userver/server/http/http_status.hpp>

#include <auth/api/v0/auth/bearer_token.hpp>
#include <auth/api/v0/utils/auth_error_mapper.hpp>
#include <auth/api/v0/utils/json_error.hpp>
#include <auth/components/auth_application_component.hpp>
#include <auth/services/usecases/authentication_service.hpp>
#include <auth/services/usecases/session_service.hpp>

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
SessionsRevokeAllHandler::SessionsRevokeAllHandler(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context)
    : HttpHandlerJsonBase(config, context),
      authentication_service_(
          context.FindComponent<components::AuthApplicationComponent>()
              .GetAuthenticationService()),
      session_service_(
          context.FindComponent<components::AuthApplicationComponent>()
              .GetSessionService()) {}

SessionsRevokeAllHandler::Value
SessionsRevokeAllHandler::HandleRequestJsonThrow(const HttpRequest& request,
                                                 const Value&,
                                                 RequestContext&) const {
  ClearRefreshCookie(request);

  const auto access_token = auth::ExtractBearerToken(request);
  if (!access_token) {
    request.GetHttpResponse().SetStatus(
        userver::server::http::HttpStatus::kUnauthorized);
    return utils::ErrorResponse("auth.missing_access_token",
                                "missing access token");
  }

  try {
    const auto context =
        authentication_service_.AuthenticateAccessToken(*access_token);
    session_service_.RevokeAllSessions(context);

    request.GetHttpResponse().SetStatus(
        userver::server::http::HttpStatus::kNoContent);
    return {};
  } catch (const std::exception& e) {
    return utils::AuthErrorResponse(request, e);
  }
}
}  // namespace smirkly::auth::api::v0::handlers
