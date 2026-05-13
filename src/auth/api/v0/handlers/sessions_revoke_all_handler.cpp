#include <auth/api/v0/handlers/sessions_revoke_all_handler.hpp>

#include <chrono>

#include <userver/components/component_context.hpp>
#include <userver/server/http/http_response_cookie.hpp>
#include <userver/server/http/http_status.hpp>

#include <auth/api/v0/auth/bearer_token.hpp>
#include <auth/api/v0/utils/json_error.hpp>
#include <auth/components/auth_service_component.hpp>
#include <auth/services/errors/access_token_errors.hpp>

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
    SessionsRevokeAllHandler::SessionsRevokeAllHandler(
        const userver::components::ComponentConfig &config,
        const userver::components::ComponentContext &context
    )
        : HttpHandlerJsonBase(config, context),
          auth_service_(
              context.FindComponent<components::AuthServiceComponent>().GetAuthService()
          ) {
    }

    SessionsRevokeAllHandler::Value SessionsRevokeAllHandler::HandleRequestJsonThrow(
        const HttpRequest &request,
        const Value &,
        RequestContext &
    ) const {
        ClearRefreshCookie(request);

        const auto access_token = auth::ExtractBearerToken(request);
        if (!access_token) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kUnauthorized);
            return utils::ErrorResponse("auth.missing_access_token", "missing access token");
        }

        try {
            const auto context = auth_service_.AuthenticateAccessToken(*access_token);
            auth_service_.RevokeAllSessions(context);

            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kNoContent);
            return {};
        } catch (const services::errors::AccessTokenError &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kUnauthorized);
            return utils::ErrorResponse("auth.invalid_access_token", "invalid access token");
        }
    }
}
