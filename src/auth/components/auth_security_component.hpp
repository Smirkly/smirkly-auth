#pragma once

#include <memory>
#include <string>
#include <string_view>

#include <userver/components/loggable_component_base.hpp>
#include <userver/yaml_config/schema.hpp>

namespace smirkly::auth::services::ports {
class PasswordHasher;
class VerificationCodeGenerator;
}  // namespace smirkly::auth::services::ports

namespace smirkly::auth::services::ports::security {
class JwtTokenProvider;
}  // namespace smirkly::auth::services::ports::security

namespace smirkly::auth::services::ports::support {
class IdGenerator;
}  // namespace smirkly::auth::services::ports::support

namespace smirkly::auth::components {

class AuthSecurityComponent final
    : public userver::components::LoggableComponentBase {
 public:
  static constexpr std::string_view kName = "auth-security";

  AuthSecurityComponent(const userver::components::ComponentConfig& cfg,
                        const userver::components::ComponentContext& ctx);

  ~AuthSecurityComponent() override;

  static userver::yaml_config::Schema GetStaticConfigSchema();

  services::ports::security::JwtTokenProvider& GetJwtTokenProvider() noexcept;

  const services::ports::security::JwtTokenProvider& GetJwtTokenProvider()
      const noexcept;

  services::ports::PasswordHasher& GetPasswordHasher() noexcept;

  const services::ports::PasswordHasher& GetPasswordHasher() const noexcept;

  services::ports::VerificationCodeGenerator&
  GetVerificationCodeGenerator() noexcept;

  const services::ports::VerificationCodeGenerator&
  GetVerificationCodeGenerator() const noexcept;

  services::ports::support::IdGenerator& GetIdGenerator() noexcept;

  const services::ports::support::IdGenerator& GetIdGenerator() const noexcept;

  const std::string& GetPublicJwksJson() const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace smirkly::auth::components
