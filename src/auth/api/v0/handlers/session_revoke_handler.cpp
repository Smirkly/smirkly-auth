#include <auth/api/v0/handlers/session_revoke_handler.hpp>

#include <userver/components/component_context.hpp>
#include <userver/server/http/http_status.hpp>

#include <auth/api/v0/auth/bearer_token.hpp>
#include <auth/api/v0/utils/json_error.hpp>
#include <auth/components/auth_service_component.hpp>
#include <auth/services/errors/access_token_errors.hpp>

namespace smirkly::auth::api::v0::handlers {
    SessionRevokeHandler::SessionRevokeHandler(
        const userver::components::ComponentConfig &config,
        const userver::components::ComponentContext &context
    )
        : HttpHandlerJsonBase(config, context),
          auth_service_(
              context.FindComponent<components::AuthServiceComponent>().GetAuthService()
          ) {
    }

    SessionRevokeHandler::Value SessionRevokeHandler::HandleRequestJsonThrow(
        const HttpRequest &request,
        const Value &,
        RequestContext &
    ) const {
        const auto access_token = auth::ExtractBearerToken(request);
        if (!access_token) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kUnauthorized);
            return utils::ErrorResponse("auth.missing_access_token", "missing access token");
        }

        try {
            const auto context = auth_service_.AuthenticateAccessToken(*access_token);
            auth_service_.RevokeSession(context, request.GetPathArg("session_id"));

            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kNoContent);
            return {};
        } catch (const services::errors::AccessTokenError &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kUnauthorized);
            return utils::ErrorResponse("auth.invalid_access_token", "invalid access token");
        } catch (const services::errors::SessionForbidden &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kForbidden);
            return utils::ErrorResponse("auth.session_forbidden", "session belongs to another user");
        } catch (const services::errors::SessionNotFound &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kNotFound);
            return utils::ErrorResponse("auth.session_not_found", "session not found");
        }
    }
}
