#pragma once

#include <memory>
#include <string>
#include <string_view>

#include <userver/components/loggable_component_base.hpp>

namespace smirkly::auth::services::usecases {
class AuthService;
}

namespace smirkly::auth::components {
class AuthServiceComponent final
    : public userver::components::LoggableComponentBase {
 public:
  static constexpr std::string_view kName = "auth-service";

  AuthServiceComponent(const userver::components::ComponentConfig& cfg,
                       const userver::components::ComponentContext& ctx);

  ~AuthServiceComponent() override;

  static userver::yaml_config::Schema GetStaticConfigSchema();

  services::usecases::AuthService& GetAuthService() noexcept;

  const services::usecases::AuthService& GetAuthService() const noexcept;

  const std::string& GetPublicJwksJson() const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
}  // namespace smirkly::auth::components
