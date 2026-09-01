#pragma once

#include <userver/server/handlers/http_handler_json_base.hpp>

namespace smirkly::auth::services::usecases {
class AuthenticationService;
class IdentityService;
}  // namespace smirkly::auth::services::usecases

namespace smirkly::auth::api::v0::handlers {
class MeHandler final : public userver::server::handlers::HttpHandlerJsonBase {
 public:
  static constexpr std::string_view kName = "handler-auth-me";

  MeHandler(const userver::components::ComponentConfig& config,
            const userver::components::ComponentContext& context);

  Value HandleRequestJsonThrow(const HttpRequest& request, const Value& body,
                               RequestContext& context) const override;

 private:
  services::usecases::AuthenticationService& authentication_service_;
  services::usecases::IdentityService& identity_service_;
};
}  // namespace smirkly::auth::api::v0::handlers
