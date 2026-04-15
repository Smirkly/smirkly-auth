#include "sign_in_handler.hpp"

#include <auth/api/v0/handlers/sign_up_handler.hpp>

#include <userver/server/handlers/exceptions.hpp>
#include <userver/components/component_context.hpp>

#include <auth/api/v0/dto/sign_up_request.hpp>
#include <auth/components/auth_service_component.hpp>
#include <auth/infra/mapping/dto_mappers.hpp>
#include <auth/services/usecases/auth_service.hpp>

namespace smirkly::auth::api::v0::handlers {
    SignInHandler::SignInHandler(const userver::components::ComponentConfig &config,
                                 const userver::components::ComponentContext &context) : HttpHandlerJsonBase(
            config, context),
        auth_service_(context.FindComponent<smirkly::auth::components::AuthServiceComponent>().GetAuthService()) {
    }

    SignInHandler::Value SignInHandler::HandleRequestJsonThrow(
        const HttpRequest &request,
        const Value &body,
        RequestContext &
    ) const {
        userver::formats::json::ValueBuilder response;

        response["user"]["id"] = "test-user-id";
        response["user"]["username"] = "capy";
        response["user"]["email"] = "capy@example.com";
        response["user"]["is_email_verified"] = true;

        response["tokens"]["access_token"] = "test-access-token";
        response["tokens"]["refresh_token"] = "test-refresh-token";

        return response.ExtractValue();
    }
};
