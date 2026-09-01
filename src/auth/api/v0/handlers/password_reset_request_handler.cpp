#include <auth/api/v0/handlers/password_reset_request_handler.hpp>

#include <string>

#include <userver/components/component_context.hpp>
#include <userver/server/http/http_status.hpp>

#include <auth/api/v0/utils/auth_error_mapper.hpp>
#include <auth/api/v0/utils/json_error.hpp>
#include <auth/api/v0/utils/json_request.hpp>
#include <auth/components/auth_application_component.hpp>
#include <auth/components/auth_http_component.hpp>
#include <auth/infra/http/request_meta_extractor.hpp>
#include <auth/services/contracts/password_reset.hpp>
#include <auth/services/usecases/password_service.hpp>

namespace smirkly::auth::api::v0::handlers {

namespace {

bool IsValidEmailShape(const std::string& email) {
  return !email.empty() && email.size() <= 320 &&
         email.find('@') != std::string::npos;
}

}  // namespace

PasswordResetRequestHandler::PasswordResetRequestHandler(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context)
    : HttpHandlerJsonBase(config, context),
      password_service_(
          context.FindComponent<components::AuthApplicationComponent>()
              .GetPasswordService()),
      request_meta_extractor_(
          context.FindComponent<components::AuthHttpComponent>()
              .GetRequestMetaExtractor()) {}

PasswordResetRequestHandler::Value
PasswordResetRequestHandler::HandleRequestJsonThrow(const HttpRequest& request,
                                                    const Value& body,
                                                    RequestContext&) const {
  const auto email = utils::GetString(body, "email");
  if (!email || !IsValidEmailShape(*email)) {
    return utils::BadRequestResponse(request,
                                     "auth.password_reset.validation_failed",
                                     "invalid email format");
  }

  try {
    password_service_.RequestReset(
        services::contracts::RequestPasswordResetCommand{.email = *email},
        request_meta_extractor_.Extract(request));
  } catch (const std::exception& e) {
    return utils::AuthErrorResponse(request, e);
  }

  request.GetHttpResponse().SetStatus(
      userver::server::http::HttpStatus::kNoContent);
  return {};
}

}  // namespace smirkly::auth::api::v0::handlers
