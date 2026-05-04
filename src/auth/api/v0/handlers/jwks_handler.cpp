#include <auth/api/v0/handlers/jwks_handler.hpp>

#include <userver/components/component_context.hpp>
#include <userver/formats/json.hpp>

namespace smirkly::auth::api::v0::handlers {
JwksHandler::JwksHandler(const userver::components::ComponentConfig& config,
                         const userver::components::ComponentContext& context)
    : HttpHandlerJsonBase(config, context),
      auth_component_(context.FindComponent<
                      smirkly::auth::components::AuthServiceComponent>()) {}

JwksHandler::Value JwksHandler::HandleRequestJsonThrow(
    const HttpRequest& request, const Value&, RequestContext&) const {
  request.GetHttpResponse().SetHeader(std::string_view{"Cache-Control"},
                                      std::string{"public, max-age=300"});

  return userver::formats::json::FromString(
      auth_component_.GetPublicJwksJson());
}
}  // namespace smirkly::auth::api::v0::handlers
