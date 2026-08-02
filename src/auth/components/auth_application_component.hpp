#pragma once

#include <memory>
#include <string_view>

#include <userver/components/loggable_component_base.hpp>

namespace smirkly::auth::services::usecases {
class AuthenticationService;
class IdentityService;
class PasswordService;
class SessionService;
}  // namespace smirkly::auth::services::usecases

namespace smirkly::auth::components {

class AuthApplicationComponent final
    : public userver::components::LoggableComponentBase {
 public:
  static constexpr std::string_view kName = "auth-service";

  AuthApplicationComponent(
      const userver::components::ComponentConfig& config,
      const userver::components::ComponentContext& context);

  ~AuthApplicationComponent() override;

  static userver::yaml_config::Schema GetStaticConfigSchema();

  services::usecases::AuthenticationService&
  GetAuthenticationService() noexcept;

  services::usecases::IdentityService& GetIdentityService() noexcept;

  services::usecases::PasswordService& GetPasswordService() noexcept;

  services::usecases::SessionService& GetSessionService() noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace smirkly::auth::components
