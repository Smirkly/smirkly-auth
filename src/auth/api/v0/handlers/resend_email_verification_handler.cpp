#include <auth/api/v0/handlers/resend_email_verification_handler.hpp>

#include <string>

#include <userver/components/component_context.hpp>
#include <userver/server/http/http_status.hpp>

#include <auth/api/v0/utils/auth_error_mapper.hpp>
#include <auth/api/v0/utils/json_error.hpp>
#include <auth/api/v0/utils/json_request.hpp>
#include <auth/components/auth_application_component.hpp>
#include <auth/components/auth_http_component.hpp>
#include <auth/infra/http/request_meta_extractor.hpp>
#include <auth/services/usecases/identity_service.hpp>

namespace smirkly::auth::api::v0::handlers {
ResendEmailVerificationHandler::ResendEmailVerificationHandler(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context)
    : HttpHandlerJsonBase(config, context),
      identity_service_(
          context.FindComponent<components::AuthApplicationComponent>()
              .GetIdentityService()),
      request_meta_extractor_(
          context.FindComponent<smirkly::auth::components::AuthHttpComponent>()
              .GetRequestMetaExtractor()) {}

ResendEmailVerificationHandler::Value
ResendEmailVerificationHandler::HandleRequestJsonThrow(
    const HttpRequest& request, const Value& body, RequestContext&) const {
  const auto email = utils::GetString(body, "email");

  if (!email || email->empty()) {
    return utils::BadRequestResponse(
        request, "auth.resend_email_verification.validation_failed",
        "email is required");
  }

  if (email->size() > 320 || email->find('@') == std::string::npos) {
    return utils::BadRequestResponse(
        request, "auth.resend_email_verification.validation_failed",
        "invalid email format");
  }

  try {
    identity_service_.ResendEmailVerification(
        services::contracts::ResendEmailVerificationCommand{.email = *email},
        request_meta_extractor_.Extract(request));
  } catch (const std::exception& e) {
    return utils::AuthErrorResponse(
        request, e, utils::AuthErrorContext::kResendEmailVerification);
  }

  request.GetHttpResponse().SetStatus(
      userver::server::http::HttpStatus::kNoContent);
  return {};
}
}  // namespace smirkly::auth::api::v0::handlers
