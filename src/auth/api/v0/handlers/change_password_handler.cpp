#include <auth/api/v0/handlers/change_password_handler.hpp>

#include <chrono>

#include <userver/components/component_context.hpp>
#include <userver/server/http/http_response_cookie.hpp>
#include <userver/server/http/http_status.hpp>

#include <auth/api/v0/auth/bearer_token.hpp>
#include <auth/api/v0/utils/json_error.hpp>
#include <auth/components/auth_service_component.hpp>
#include <auth/services/contracts/change_password.hpp>
#include <auth/services/errors/access_token_errors.hpp>
#include <auth/services/errors/change_password_errors.hpp>

namespace {
    void ClearRefreshCookie(const userver::server::http::HttpRequest &request) {
        request.GetHttpResponse().SetCookie(
            userver::server::http::Cookie("refresh_token", "")
                .SetHttpOnly()
                .SetSecure()
                .SetPath("/auth/v0/refresh")
                .SetSameSite("Strict")
                .SetMaxAge(std::chrono::seconds{0})
        );
    }
}

namespace smirkly::auth::api::v0::handlers {
    ChangePasswordHandler::ChangePasswordHandler(
        const userver::components::ComponentConfig &config,
        const userver::components::ComponentContext &context
    )
        : HttpHandlerJsonBase(config, context),
          auth_service_(
              context.FindComponent<components::AuthServiceComponent>().GetAuthService()
          ) {
    }

    ChangePasswordHandler::Value ChangePasswordHandler::HandleRequestJsonThrow(
        const HttpRequest &request,
        const Value &body,
        RequestContext &
    ) const {
        const auto access_token = auth::ExtractBearerToken(request);
        if (!access_token) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kUnauthorized);
            return utils::ErrorResponse("auth.missing_access_token", "missing access token");
        }

        if (!body.HasMember("current_password") || !body.HasMember("new_password")) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kBadRequest);
            return utils::ErrorResponse(
                "auth.change_password.validation_failed",
                "current_password and new_password are required"
            );
        }

        const services::contracts::ChangePasswordCommand cmd{
            .current_password = body["current_password"].As<std::string>(),
            .new_password = body["new_password"].As<std::string>(),
        };

        try {
            const auto context = auth_service_.AuthenticateAccessToken(*access_token);
            auth_service_.ChangePassword(context, cmd);
            ClearRefreshCookie(request);

            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kNoContent);
            return {};
        } catch (const services::errors::AccessTokenError &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kUnauthorized);
            return utils::ErrorResponse("auth.invalid_access_token", "invalid access token");
        } catch (const services::errors::InvalidCurrentPassword &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kUnauthorized);
            return utils::ErrorResponse("auth.invalid_current_password", "invalid current password");
        } catch (const services::errors::ChangePasswordValidation &e) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kBadRequest);
            return utils::ErrorResponse("auth.change_password.validation_failed", e.what());
        }
    }
}
