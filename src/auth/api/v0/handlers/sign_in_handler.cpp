#include <auth/api/v0/handlers/sign_in_handler.hpp>

#include <userver/components/component_context.hpp>
#include <userver/server/handlers/exceptions.hpp>

#include <auth/api/v0/dto/sign_in_request.hpp>
#include <auth/components/auth_service_component.hpp>
#include <auth/infra/mapping/dto_mappers.hpp>
#include <auth/services/errors/sign_in_errors.hpp>

namespace smirkly::auth::api::v0::handlers {
    SignInHandler::SignInHandler(
        const userver::components::ComponentConfig &config,
        const userver::components::ComponentContext &context
    )
        : HttpHandlerJsonBase(config, context),
          auth_service_(
              context.FindComponent<smirkly::auth::components::AuthServiceComponent>().GetAuthService()
          ) {
    }

    SignInHandler::Value SignInHandler::HandleRequestJsonThrow(
        const HttpRequest &request,
        const Value &body,
        RequestContext &
    ) const {
        try {
            const auto dto = body.As<dto::SignInRequest>();
            const auto cmd = infra::mapping::ToDomain(dto);
            const auto meta = infra::mapping::ToRequestMeta(request);

            const auto result = auth_service_.SignIn(cmd, meta);

            userver::formats::json::ValueBuilder response;

            response["user"]["id"] = result.user.id;
            response["user"]["username"] = result.user.username;

            if (result.user.email) {
                response["user"]["email"] = *result.user.email;
            } else {
                response["user"]["email"] = nullptr;
            }

            if (result.user.phone) {
                response["user"]["phone"] = *result.user.phone;
            } else {
                response["user"]["phone"] = nullptr;
            }

            response["user"]["is_email_verified"] = result.user.is_email_verified;
            response["user"]["is_phone_verified"] = result.user.is_phone_verified;

            response["tokens"]["access_token"] = result.tokens.access_token;
            response["tokens"]["refresh_token"] = result.tokens.refresh_token;
            response["session_id"] = result.session_id;

            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kOk);
            return response.ExtractValue();
        } catch (const services::errors::SignInValidation &e) {
            userver::formats::json::ValueBuilder response;
            response["message"] = std::string{"sign in validation failed: "} + e.what();

            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kBadRequest);
            return response.ExtractValue();
        } catch (const services::errors::InvalidCredentials &) {
            userver::formats::json::ValueBuilder response;
            response["message"] = "invalid credentials";

            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kUnauthorized);
            return response.ExtractValue();
        } catch (const services::errors::EmailNotVerified &) {
            userver::formats::json::ValueBuilder response;
            response["message"] = "email is not verified";

            request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kForbidden);
            return response.ExtractValue();
        }
    }
}
