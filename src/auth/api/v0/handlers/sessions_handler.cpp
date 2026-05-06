#include <auth/api/v0/handlers/sessions_handler.hpp>

#include <userver/components/component_context.hpp>
#include <userver/server/http/http_status.hpp>
#include <userver/utils/datetime.hpp>

#include <auth/api/v0/auth/bearer_token.hpp>
#include <auth/api/v0/utils/json_error.hpp>
#include <auth/components/auth_service_component.hpp>
#include <auth/services/errors/access_token_errors.hpp>

namespace {
    std::string ToIsoUtc(std::chrono::system_clock::time_point value) {
        return userver::utils::datetime::UtcTimestring(
            value,
            userver::utils::datetime::kRfc3339Format
        );
    }

    userver::formats::json::Value ToSessionJson(
        const smirkly::auth::domain::models::Session &session,
        std::string_view current_session_id
    ) {
        userver::formats::json::ValueBuilder builder;
        builder["id"] = session.id;
        if (session.device_id) {
            builder["device_id"] = *session.device_id;
        } else {
            builder["device_id"] = nullptr;
        }
        if (session.ip) {
            builder["ip"] = *session.ip;
        } else {
            builder["ip"] = nullptr;
        }
        if (session.user_agent) {
            builder["user_agent"] = *session.user_agent;
        } else {
            builder["user_agent"] = nullptr;
        }
        builder["created_at"] = ToIsoUtc(session.created_at);
        if (session.last_used_at) {
            builder["last_used_at"] = ToIsoUtc(*session.last_used_at);
        } else {
            builder["last_used_at"] = nullptr;
        }
        builder["expires_at"] = ToIsoUtc(session.expires_at);
        builder["current"] = session.id == current_session_id;
        return builder.ExtractValue();
    }
}

namespace smirkly::auth::api::v0::handlers {
    SessionsHandler::SessionsHandler(
        const userver::components::ComponentConfig &config,
        const userver::components::ComponentContext &context
    )
        : HttpHandlerJsonBase(config, context),
          auth_service_(
              context.FindComponent<components::AuthServiceComponent>().GetAuthService()
          ) {
    }

    SessionsHandler::Value SessionsHandler::HandleRequestJsonThrow(
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
            const auto result = auth_service_.ListSessions(context);

            userver::formats::json::ValueBuilder sessions(
                userver::formats::json::Type::kArray
            );
            for (const auto &session: result.sessions) {
                sessions.PushBack(ToSessionJson(session, context.session_id));
            }

            userver::formats::json::ValueBuilder response;
            response["sessions"] = sessions.ExtractValue();

            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kOk);
            return response.ExtractValue();
        } catch (const services::errors::AccessTokenError &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kUnauthorized);
            return utils::ErrorResponse("auth.invalid_access_token", "invalid access token");
        }
    }
}
