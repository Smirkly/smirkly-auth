#include <auth/api/v0/handlers/refresh_token_handler.hpp>

#include <userver/components/component_context.hpp>
#include <userver/http/common_headers.hpp>
#include <userver/server/handlers/exceptions.hpp>
#include <userver/server/http/http_response_cookie.hpp>

#include <auth/components/auth_service_component.hpp>
#include <auth/infra/mapping/dto_mappers.hpp>
#include <auth/services/errors/refresh_errors.hpp>


namespace smirkly::auth::api::v0::handlers {
    RefreshHandler::RefreshHandler(
        const userver::components::ComponentConfig &config,
        const userver::components::ComponentContext &context
    )
        : HttpHandlerJsonBase(config, context),
          auth_service_(
              context.FindComponent<smirkly::auth::components::AuthServiceComponent>().GetAuthService()
          ) {
    }


    RefreshHandler::Value RefreshHandler::HandleRequestJsonThrow(
        const HttpRequest &request,
        const Value &body,
        RequestContext &
    ) const {
        try {
            const auto refresh_token = request.GetCookie("refresh_token");
            if (refresh_token.empty()) {
                userver::formats::json::ValueBuilder response;
                response["message"] = "invalid refresh token";

                request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kUnauthorized);
                return response.ExtractValue();
            }

            const auto meta = infra::mapping::ToRequestMeta(request);

            const services::contracts::RefreshCommand cmd = {
                .refresh_token = std::string{refresh_token}
            };

            const auto result = auth_service_.Refresh(cmd, meta);

            // request.GetHttpResponse().SetCookie(
            //     userver::server::http::Cookie("refresh_token", result.tokens.refresh_token)
            //         .SetHttpOnly()
            //         .SetSecure()
            //         .SetPath("/auth/v0/refresh")
            //         .SetSameSite("Strict")
            // );

            userver::formats::json::ValueBuilder response;
            response["tokens"]["access_token"] = result.access_token;
            response["session_id"] = result.session_id;

            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kOk);
            return response.ExtractValue();
        } catch (const services::errors::InvalidRefreshToken &) {
            userver::formats::json::ValueBuilder response;
            response["message"] = "invalid refresh token";

            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kUnauthorized);
            return response.ExtractValue();
        } catch (const services::errors::RefreshSessionNotFound &) {
            userver::formats::json::ValueBuilder response;
            response["message"] = "invalid refresh token";

            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kUnauthorized);
            return response.ExtractValue();
        } catch (const services::errors::RefreshSessionRevoked &) {
            userver::formats::json::ValueBuilder response;
            response["message"] = "invalid refresh token";

            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kUnauthorized);
            return response.ExtractValue();
        } catch (const services::errors::RefreshSessionExpired &) {
            userver::formats::json::ValueBuilder response;
            response["message"] = "invalid refresh token";

            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kUnauthorized);
            return response.ExtractValue();
        }
    }
}
