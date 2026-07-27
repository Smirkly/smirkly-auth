#include <auth/api/v0/handlers/verify_email_handler.hpp>

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

#include <userver/components/component_context.hpp>
#include <userver/server/http/http_status.hpp>

#include <auth/api/v0/utils/auth_error_mapper.hpp>
#include <auth/api/v0/utils/json_error.hpp>
#include <auth/api/v0/utils/json_request.hpp>
#include <auth/components/auth_http_component.hpp>
#include <auth/components/auth_service_component.hpp>
#include <auth/infra/http/request_meta_extractor.hpp>
#include <auth/services/errors/verify_email_errors.hpp>
#include <auth/services/policies/verification_code_policy.hpp>

namespace smirkly::auth::api::v0::handlers {
VerifyEmailHandler::VerifyEmailHandler(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context)
    : HttpHandlerJsonBase(config, context),
      auth_service_(
          context
              .FindComponent<smirkly::auth::components::AuthServiceComponent>()
              .GetAuthService()),
      request_meta_extractor_(
          context.FindComponent<smirkly::auth::components::AuthHttpComponent>()
              .GetRequestMetaExtractor()) {}

VerifyEmailHandler::Value VerifyEmailHandler::HandleRequestJsonThrow(
    const HttpRequest& request, const Value& body, RequestContext&) const {
  const auto email = utils::GetString(body, "email");
  const auto code = utils::GetString(body, "code");

  if (!email || !code || email->empty() || code->empty()) {
    return utils::BadRequestResponse(request,
                                     "auth.verify_email.validation_failed",
                                     "email and code are required");
  }

  if (email->size() > 320 || email->find('@') == std::string::npos) {
    return utils::BadRequestResponse(
        request, "auth.verify_email.validation_failed", "invalid email format");
  }

  const bool invalid_code =
      code->size() != services::policies::kVerificationCodeLength ||
      !std::all_of(code->begin(), code->end(),
                   [](unsigned char c) { return std::isdigit(c); });

  if (invalid_code) {
    return utils::BadRequestResponse(
        request, "auth.verify_email.validation_failed", "invalid code format");
  }

  const auto cmd =
      services::contracts::VerifyEmailCommand{.email = *email, .code = *code};

  try {
    auth_service_.VerifyEmail(cmd, request_meta_extractor_.Extract(request));
  } catch (const services::errors::AlreadyVerified&) {
    request.GetHttpResponse().SetStatus(
        userver::server::http::HttpStatus::kNoContent);
    return {};
  } catch (const std::exception& e) {
    return utils::AuthErrorResponse(request, e,
                                    utils::AuthErrorContext::kVerifyEmail);
  }

  request.GetHttpResponse().SetStatus(
      userver::server::http::HttpStatus::kNoContent);
  return {};
}
}  // namespace smirkly::auth::api::v0::handlers
