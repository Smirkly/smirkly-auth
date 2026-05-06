#pragma once

#include <userver/server/handlers/http_handler_json_base.hpp>

#include <auth/components/auth_service_component.hpp>

namespace smirkly::auth::api::v0::handlers {
class JwksHandler final
    : public userver::server::handlers::HttpHandlerJsonBase {
 public:
  static constexpr std::string_view kName = "handler-auth-jwks";

  JwksHandler(const userver::components::ComponentConfig& config,
              const userver::components::ComponentContext& context);

  Value HandleRequestJsonThrow(const HttpRequest& request, const Value& body,
                               RequestContext& context) const override;

 private:
  smirkly::auth::components::AuthServiceComponent& auth_component_;
};
}  // namespace smirkly::auth::api::v0::handlers
