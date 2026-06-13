#include <auth/components/auth_service_component.hpp>

#include <string>

#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

#include <auth/components/auth_infra_component.hpp>
#include <auth/components/auth_security_component.hpp>
#include <auth/config/auth_service_config.hpp>
#include <auth/services/usecases/auth_service.hpp>

namespace smirkly::auth::components {
struct AuthServiceComponent::Impl {
  config::AuthServiceSettings settings;
  AuthInfraComponent& infra;
  AuthSecurityComponent& security;
  services::usecases::AuthService auth_service;

  Impl(const userver::components::ComponentConfig& cfg,
       const userver::components::ComponentContext& ctx)
      : settings(config::ParseAuthServiceSettings(cfg)),
        infra(ctx.FindComponent<AuthInfraComponent>(
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
                     security.GetIdGenerator(),
                     services::policies::SessionPolicy{
                         .refresh_token_ttl = security.GetRefreshTokenTtl(),
                         .activity_update_threshold =
                             settings.session.activity_update_threshold
                     },
                     settings.sign_in,
                     settings.email_verification) {}
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
  sign-in:
    type: object
    description: Sign-in policy
    additionalProperties: false
    properties:
      require-verified-email:
        type: boolean
        description: Reject password sign-in for accounts with an unverified email address
        default: false
  session-activity:
    type: object
    description: Authenticated session activity tracking
    additionalProperties: false
    properties:
      update-threshold-seconds:
        type: integer
        description: Minimum interval between last_used_at writes for one active session
        minimum: 0
        default: 300
  email-verification:
    type: object
    description: Email verification limits
    additionalProperties: false
    properties:
      max-code-attempts:
        type: integer
        description: Maximum invalid attempts for one active verification code
        minimum: 1
        default: 5
      rate-limit-window-seconds:
        type: integer
        description: Rolling window for email verification attempt limits
        minimum: 1
        default: 900
      max-attempts-per-email:
        type: integer
        description: Maximum verification attempts per email in the rolling window; 0 disables this limit
        minimum: 0
        default: 5
      max-attempts-per-user:
        type: integer
        description: Maximum verification attempts per user in the rolling window; 0 disables this limit
        minimum: 0
        default: 5
      max-attempts-per-ip:
        type: integer
        description: Maximum verification attempts per IP in the rolling window; 0 disables this limit
        minimum: 0
        default: 50
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
