#include <auth/api/v0/handlers/verify_email_handler.hpp>

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

#include <userver/components/component_context.hpp>
#include <userver/server/http/http_status.hpp>

#include <auth/api/v0/utils/json_error.hpp>
#include <auth/components/auth_http_component.hpp>
#include <auth/components/auth_service_component.hpp>
#include <auth/infra/http/request_meta_extractor.hpp>
#include <auth/services/errors/verify_email_errors.hpp>


namespace smirkly::auth::api::v0::handlers {
    VerifyEmailHandler::VerifyEmailHandler(const userver::components::ComponentConfig &config,
                                           const userver::components::ComponentContext &
                                           context)
        : HttpHandlerJsonBase(config, context),
          auth_service_(context.FindComponent<smirkly::auth::components::AuthServiceComponent>().GetAuthService()),
          request_meta_extractor_(
              context.FindComponent<smirkly::auth::components::AuthHttpComponent>().GetRequestMetaExtractor()
          ) {
    }

    VerifyEmailHandler::Value VerifyEmailHandler::HandleRequestJsonThrow(
        const HttpRequest &request,
        const Value &body,
        RequestContext &
    ) const {
        if (!body.HasMember("email") || !body.HasMember("code")) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kBadRequest);
            return utils::ErrorResponse("auth.verify_email.validation_failed", "email and code are required");
        }

        const auto email = body["email"].As<std::string>();
        const auto code = body["code"].As<std::string>();

        if (email.empty() || code.empty()) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kBadRequest);
            return utils::ErrorResponse("auth.verify_email.validation_failed", "email and code are required");
        }

        if (email.size() > 320 || email.find('@') == std::string::npos) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kBadRequest);
            return utils::ErrorResponse("auth.verify_email.validation_failed", "invalid email format");
        }

        const bool invalid_code = code.size() != 6 || !std::all_of(
                                      code.begin(), code.end(),
                                      [](unsigned char c) { return std::isdigit(c); }
                                  );

        if (invalid_code) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kBadRequest);
            return utils::ErrorResponse("auth.verify_email.validation_failed", "invalid code format");
        }

        const auto cmd = services::contracts::VerifyEmailCommand{
            .email = std::string{email},
            .code = std::string{code}
        };

        try {
            auth_service_.VerifyEmail(cmd, request_meta_extractor_.Extract(request));
        } catch (const services::errors::AlreadyVerified &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kNoContent);
            return {};
        } catch (const services::errors::UserNotFound &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kNotFound);
            return utils::ErrorResponse("auth.verify_email.user_not_found", "user not found");
        } catch (const services::errors::InvalidCode &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kBadRequest);
            return utils::ErrorResponse("auth.verify_email.invalid_code", "invalid verification code");
        } catch (const services::errors::TooManyVerificationAttempts &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kTooManyRequests);
            return utils::ErrorResponse("auth.verify_email.too_many_attempts", "too many verification attempts");
        } catch (const services::errors::CodeExpired &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kGone);
            return utils::ErrorResponse("auth.verify_email.code_expired", "verification code expired or not found");
        } catch (const services::errors::VerifyEmailError &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kBadRequest);
            return utils::ErrorResponse("auth.verify_email.failed", "email verification failed");
        }

        request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kNoContent);
        return {};
    }
}
