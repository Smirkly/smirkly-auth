#pragma once

#include <string_view>

#include <userver/server/handlers/http_handler_json_base.hpp>

namespace smirkly::auth::api::health {

class LivenessHandler final
    : public userver::server::handlers::HttpHandlerJsonBase {
 public:
  static constexpr std::string_view kName = "handler-health-live";

  LivenessHandler(const userver::components::ComponentConfig& config,
                  const userver::components::ComponentContext& context);

  Value HandleRequestJsonThrow(const HttpRequest& request, const Value& body,
                               RequestContext& context) const override;
};

}  // namespace smirkly::auth::api::health
