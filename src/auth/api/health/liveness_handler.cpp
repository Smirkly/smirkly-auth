#include <auth/api/health/liveness_handler.hpp>

#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/formats/json/value_builder.hpp>
#include <userver/server/http/http_status.hpp>

namespace smirkly::auth::api::health {

LivenessHandler::LivenessHandler(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context)
    : HttpHandlerJsonBase(config, context, true) {}

LivenessHandler::Value LivenessHandler::HandleRequestJsonThrow(
    const HttpRequest& request, const Value&, RequestContext&) const {
  request.GetHttpResponse().SetStatus(userver::server::http::HttpStatus::kOk);

  userver::formats::json::ValueBuilder response;
  response["status"] = "ok";
  return response.ExtractValue();
}

}  // namespace smirkly::auth::api::health
