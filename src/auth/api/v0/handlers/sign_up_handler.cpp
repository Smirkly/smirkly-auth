#include <auth/api/v0/handlers/sign_up_handler.hpp>

#include <userver/components/component_context.hpp>
#include <userver/server/handlers/exceptions.hpp>

#include <auth/api/v0/dto/sign_up_request.hpp>
#include <auth/api/v0/utils/auth_error_mapper.hpp>
#include <auth/api/v0/utils/json_error.hpp>
#include <auth/components/auth_application_component.hpp>
#include <auth/components/auth_http_component.hpp>
#include <auth/infra/http/request_meta_extractor.hpp>
#include <auth/infra/mapping/dto_mappers.hpp>
#include <auth/services/usecases/identity_service.hpp>

namespace smirkly::auth::api::v0::handlers {
SignUpHandler::SignUpHandler(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context)
    : HttpHandlerJsonBase(config, context),
      identity_service_(
          context.FindComponent<components::AuthApplicationComponent>()
              .GetIdentityService()),
      request_meta_extractor_(
          context.FindComponent<smirkly::auth::components::AuthHttpComponent>()
              .GetRequestMetaExtractor()) {}

SignUpHandler::Value SignUpHandler::HandleRequestJsonThrow(
    const HttpRequest& request, const Value& body, RequestContext&) const {
  api::v0::dto::SignUpRequest sign_up_dto;
  try {
    sign_up_dto = api::v0::dto::SignUpRequest::FromJson(body);
  } catch (const std::exception&) {
    return utils::BadRequestResponse(request, "sign_up.validation_failed",
                                     "invalid request body");
  }

  auto sign_up_cmd = infra::mapping::ToDomain(sign_up_dto);
  const auto meta = request_meta_extractor_.Extract(request);

  try {
    auto result = identity_service_.SignUp(sign_up_cmd, meta);
    auto user_dto = infra::mapping::ToUserDto(result.user);

    userver::formats::json::ValueBuilder builder;
    builder["user"] = user_dto.ToJson();

    request.GetHttpResponse().SetStatus(
        userver::server::http::HttpStatus::kCreated);
    return builder.ExtractValue();
  } catch (const std::exception& e) {
    return utils::AuthErrorResponse(request, e);
  }
}
};  // namespace smirkly::auth::api::v0::handlers
