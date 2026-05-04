#include <auth/api/v0/handlers/me_handler.hpp>

#include <userver/components/component_context.hpp>
#include <userver/server/http/http_status.hpp>

#include <auth/api/v0/auth/bearer_token.hpp>
#include <auth/api/v0/utils/json_error.hpp>
#include <auth/components/auth_service_component.hpp>
#include <auth/infra/mapping/dto_mappers.hpp>
#include <auth/services/errors/access_token_errors.hpp>

namespace smirkly::auth::api::v0::handlers {
    MeHandler::MeHandler(
        const userver::components::ComponentConfig &config,
        const userver::components::ComponentContext &context
    )
        : HttpHandlerJsonBase(config, context),
          auth_service_(
              context.FindComponent<components::AuthServiceComponent>().GetAuthService()
          ) {
    }

    MeHandler::Value MeHandler::HandleRequestJsonThrow(
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
            const auto result = auth_service_.GetMe(context);
            const auto user_dto = infra::mapping::ToUserDto(result.user);

            userver::formats::json::ValueBuilder response;
            response["user"] = user_dto.ToJson();
            response["session_id"] = result.session_id;

            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kOk);
            return response.ExtractValue();
        } catch (const services::errors::AccessTokenError &) {
            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kUnauthorized);
            return utils::ErrorResponse("auth.invalid_access_token", "invalid access token");
        }
    }
}
