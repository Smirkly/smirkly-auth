#include <auth/api/v0/handlers/sign_up_handler.hpp>

#include <userver/server/handlers/exceptions.hpp>
#include <userver/components/component_context.hpp>

#include <auth/api/v0/dto/sign_up_request.hpp>
#include <auth/components/auth_service_component.hpp>
#include <auth/infra/mapping/dto_mappers.hpp>
#include <auth/services/usecases/auth_service.hpp>

namespace smirkly::auth::api::v0::handlers {
    SignUpHandler::SignUpHandler(const userver::components::ComponentConfig &config,
                                 const userver::components::ComponentContext &context) : HttpHandlerJsonBase(
            config, context),
        auth_service_(context.FindComponent<smirkly::auth::components::AuthServiceComponent>().GetAuthService()) {
    }

    SignUpHandler::Value SignUpHandler::HandleRequestJsonThrow(
        const HttpRequest &request,
        const Value &body,
        RequestContext &
    ) const {
        const auto sign_up_dto = api::v0::dto::SignUpRequest::FromJson(body);
        auto sign_up_cmd = infra::mapping::ToDomain(sign_up_dto);

        auto result = auth_service_.SignUp(sign_up_cmd);
        auto user_dto = infra::mapping::ToUserDto(result.user);

        userver::formats::json::ValueBuilder builder;
        builder["user"] = user_dto.ToJson();

        request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kCreated);
        return builder.ExtractValue();
    }
};
