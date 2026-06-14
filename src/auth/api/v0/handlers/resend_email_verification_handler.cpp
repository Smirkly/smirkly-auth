#include <auth/api/v0/handlers/resend_email_verification_handler.hpp>

#include <string>

#include <userver/components/component_context.hpp>
#include <userver/server/http/http_status.hpp>

#include <auth/api/v0/utils/json_error.hpp>
#include <auth/components/auth_http_component.hpp>
#include <auth/components/auth_service_component.hpp>
#include <auth/infra/http/request_meta_extractor.hpp>
#include <auth/services/errors/verify_email_errors.hpp>

namespace smirkly::auth::api::v0::handlers {
    ResendEmailVerificationHandler::ResendEmailVerificationHandler(
        const userver::components::ComponentConfig &config,
        const userver::components::ComponentContext &context)
        : HttpHandlerJsonBase(config, context),
          auth_service_(context.FindComponent<smirkly::auth::components::AuthServiceComponent>().GetAuthService()),
          request_meta_extractor_(
              context.FindComponent<smirkly::auth::components::AuthHttpComponent>().GetRequestMetaExtractor()
          ) {
    }

    ResendEmailVerificationHandler::Value ResendEmailVerificationHandler::HandleRequestJsonThrow(
        const HttpRequest &request,
        const Value &body,
        RequestContext &
    ) const {
        if (!body.HasMember("email")) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kBadRequest);
            return utils::ErrorResponse("auth.resend_email_verification.validation_failed", "email is required");
        }

        const auto email = body["email"].As<std::string>();

        if (email.empty()) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kBadRequest);
            return utils::ErrorResponse("auth.resend_email_verification.validation_failed", "email is required");
        }

        if (email.size() > 320 || email.find('@') == std::string::npos) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kBadRequest);
            return utils::ErrorResponse("auth.resend_email_verification.validation_failed", "invalid email format");
        }

        try {
            auth_service_.ResendEmailVerification(
                services::contracts::ResendEmailVerificationCommand{.email = std::string{email}},
                request_meta_extractor_.Extract(request)
            );
        } catch (const services::errors::TooManyVerificationAttempts &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kTooManyRequests);
            return utils::ErrorResponse(
                "auth.resend_email_verification.too_many_attempts",
                "too many verification attempts"
            );
        }

        request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kNoContent);
        return {};
    }
}
