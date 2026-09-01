#include <auth/api/v0/handlers/password_reset_confirm_handler.hpp>

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

PasswordResetConfirmHandler::PasswordResetConfirmHandler(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context)
    : HttpHandlerJsonBase(config, context),
      password_service_(
          context.FindComponent<components::AuthApplicationComponent>()
              .GetPasswordService()),
      request_meta_extractor_(
          context.FindComponent<components::AuthHttpComponent>()
              .GetRequestMetaExtractor()) {}

PasswordResetConfirmHandler::Value
PasswordResetConfirmHandler::HandleRequestJsonThrow(const HttpRequest& request,
                                                    const Value& body,
                                                    RequestContext&) const {
  const auto email = utils::GetString(body, "email");
  const auto token = utils::GetString(body, "token");
  const auto new_password = utils::GetString(body, "new_password");

  if (!email || !token || !new_password) {
    return utils::BadRequestResponse(
        request, "auth.password_reset.validation_failed",
        "email, token and new_password are required");
  }

  if (!IsValidEmailShape(*email)) {
    return utils::BadRequestResponse(request,
                                     "auth.password_reset.validation_failed",
                                     "invalid email format");
  }
  if (token->empty() || token->size() > 512) {
    return utils::BadRequestResponse(request,
                                     "auth.password_reset.validation_failed",
                                     "invalid token format");
  }

  try {
    password_service_.ConfirmReset(
        services::contracts::ConfirmPasswordResetCommand{
            .email = *email,
            .token = *token,
            .new_password = *new_password,
        },
        request_meta_extractor_.Extract(request));
  } catch (const std::exception& e) {
    return utils::AuthErrorResponse(request, e);
  }

  request.GetHttpResponse().SetStatus(
      userver::server::http::HttpStatus::kNoContent);
  return {};
}

}  // namespace smirkly::auth::api::v0::handlers
