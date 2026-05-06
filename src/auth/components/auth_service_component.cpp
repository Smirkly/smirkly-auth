#include <auth/components/auth_service_component.hpp>

#include <string>

#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

#include <auth/components/auth_infra_component.hpp>
#include <auth/components/auth_security_component.hpp>
#include <auth/services/usecases/auth_service.hpp>

namespace smirkly::auth::components {

struct AuthServiceComponent::Impl {
  AuthInfraComponent& infra;
  AuthSecurityComponent& security;
  services::usecases::AuthService auth_service;

  Impl(const userver::components::ComponentConfig& cfg,
       const userver::components::ComponentContext& ctx)
      : infra(ctx.FindComponent<AuthInfraComponent>(
            cfg["infra-component"].As<std::string>(
                std::string{AuthInfraComponent::kName}))),
        security(ctx.FindComponent<AuthSecurityComponent>(
            cfg["security-component"].As<std::string>(
                std::string{AuthSecurityComponent::kName}))),
        auth_service(infra.GetTransactionManager(), infra.GetUserRepository(),
                     infra.GetEmailOutboxRepository(),
                     infra.GetEmailVerificationRepository(),
                     security.GetPasswordHasher(),
                     security.GetVerificationCodeGenerator(),
                     security.GetJwtTokenProvider(),
                     infra.GetDeviceRepository(), infra.GetSessionRepository(),
                     security.GetIdGenerator()) {}
};

AuthServiceComponent::AuthServiceComponent(
    const userver::components::ComponentConfig& cfg,
    const userver::components::ComponentContext& ctx)
    : userver::components::LoggableComponentBase(cfg, ctx),
      impl_(std::make_unique<Impl>(cfg, ctx)) {}

AuthServiceComponent::~AuthServiceComponent() = default;

userver::yaml_config::Schema AuthServiceComponent::GetStaticConfigSchema() {
  using userver::components::LoggableComponentBase;
  using userver::yaml_config::MergeSchemas;

  return MergeSchemas<LoggableComponentBase>(R"(
type: object
description: Auth service component config
additionalProperties: false
properties:
  infra-component:
    type: string
    description: Auth infrastructure component name
    default: auth-infra
  security-component:
    type: string
    description: Auth security component name
    default: auth-security
)");
}

services::usecases::AuthService&
AuthServiceComponent::GetAuthService() noexcept {
  return impl_->auth_service;
}

const services::usecases::AuthService& AuthServiceComponent::GetAuthService()
    const noexcept {
  return impl_->auth_service;
}
}  // namespace smirkly::auth::components
