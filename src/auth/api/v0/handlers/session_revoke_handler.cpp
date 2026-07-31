#include <auth/api/v0/handlers/session_revoke_handler.hpp>

#include <userver/components/component_context.hpp>
#include <userver/server/http/http_status.hpp>

#include <auth/api/v0/auth/bearer_token.hpp>
#include <auth/api/v0/utils/auth_error_mapper.hpp>
#include <auth/api/v0/utils/json_error.hpp>
#include <auth/components/auth_service_component.hpp>

namespace smirkly::auth::api::v0::handlers {
SessionRevokeHandler::SessionRevokeHandler(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context)
    : HttpHandlerJsonBase(config, context),
      auth_service_(context.FindComponent<components::AuthServiceComponent>()
                        .GetAuthService()) {}

SessionRevokeHandler::Value SessionRevokeHandler::HandleRequestJsonThrow(
    const HttpRequest& request, const Value&, RequestContext&) const {
  const auto access_token = auth::ExtractBearerToken(request);
  if (!access_token) {
    request.GetHttpResponse().SetStatus(
        userver::server::http::HttpStatus::kUnauthorized);
    return utils::ErrorResponse("auth.missing_access_token",
                                "missing access token");
  }

  try {
    const auto context = auth_service_.AuthenticateAccessToken(*access_token);
    auth_service_.RevokeSession(context, request.GetPathArg("session_id"));

    request.GetHttpResponse().SetStatus(
        userver::server::http::HttpStatus::kNoContent);
    return {};
  } catch (const std::exception& e) {
    return utils::AuthErrorResponse(request, e);
  }
}
}  // namespace smirkly::auth::api::v0::handlers
