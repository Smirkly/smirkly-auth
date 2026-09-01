#include <auth/components/auth_application_component.hpp>

#include <string>

#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/dynamic_config/storage/component.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

#include <auth/components/auth_infra_component.hpp>
#include <auth/components/auth_security_component.hpp>
#include <auth/config/runtime_config_providers.hpp>
#include <auth/services/usecases/authentication_service.hpp>
#include <auth/services/usecases/identity_service.hpp>
#include <auth/services/usecases/password_service.hpp>
#include <auth/services/usecases/session_service.hpp>

namespace smirkly::auth::components {

struct AuthApplicationComponent::Impl final {
  AuthInfraComponent& infra;
  AuthSecurityComponent& security;
  config::DynamicConfigAuthRuntimePolicyProvider runtime_policy_provider;
  services::usecases::IdentityService identity_service;
  services::usecases::AuthenticationService authentication_service;
  services::usecases::SessionService session_service;
  services::usecases::PasswordService password_service;

  Impl(const userver::components::ComponentConfig& config,
       const userver::components::ComponentContext& context)
      : infra(context.FindComponent<AuthInfraComponent>(
            config["infra-component"].As<std::string>(
                std::string{AuthInfraComponent::kName}))),
        security(context.FindComponent<AuthSecurityComponent>(
            config["security-component"].As<std::string>(
                std::string{AuthSecurityComponent::kName}))),
        runtime_policy_provider(
            context.FindComponent<userver::components::DynamicConfig>()
                .GetSource(),
            services::policies::AuthRuntimePolicies{
                .session =
                    services::policies::SessionPolicy{
                        .refresh_token_ttl = security.GetRefreshTokenTtl(),
                    },
                .sign_up = services::policies::SignUpRateLimitPolicy{},
                .sign_in = services::policies::SignInPolicy{},
                .email_verification =
                    services::policies::EmailVerificationPolicy{},
                .password_reset = services::policies::PasswordResetPolicy{},
            }),
        identity_service(
            infra.GetTransactionManager(), infra.GetUserRepository(),
            infra.GetEmailOutboxRepository(),
            infra.GetEmailVerificationRepository(),
            infra.GetSignUpAttemptRepository(), security.GetPasswordHasher(),
            security.GetVerificationCodeGenerator(), {}, {}, {},
            &runtime_policy_provider),
        authentication_service(
            infra.GetTransactionManager(), infra.GetUserRepository(),
            infra.GetSignInAttemptRepository(), security.GetPasswordHasher(),
            security.GetRefreshTokenHasher(), security.GetJwtTokenProvider(),
            infra.GetDeviceRepository(), infra.GetSessionRepository(),
            security.GetIdGenerator(),
            services::policies::SessionPolicy{
                .refresh_token_ttl = security.GetRefreshTokenTtl(),
            },
            {}, &runtime_policy_provider),
        session_service(infra.GetTransactionManager(),
                        infra.GetSessionRepository()),
        password_service(
            infra.GetTransactionManager(), infra.GetUserRepository(),
            infra.GetPasswordResetRepository(),
            infra.GetEmailOutboxRepository(), infra.GetSessionRepository(),
            security.GetPasswordHasher(), security.GetRefreshTokenHasher(),
            security.GetPasswordResetTokenGenerator(), {}, {},
            &runtime_policy_provider) {}
};

AuthApplicationComponent::AuthApplicationComponent(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context)
    : userver::components::LoggableComponentBase(config, context),
      impl_(std::make_unique<Impl>(config, context)) {}

AuthApplicationComponent::~AuthApplicationComponent() = default;

userver::yaml_config::Schema AuthApplicationComponent::GetStaticConfigSchema() {
  using userver::components::LoggableComponentBase;
  using userver::yaml_config::MergeSchemas;

  return MergeSchemas<LoggableComponentBase>(R"(
type: object
description: Auth application component config
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

services::usecases::AuthenticationService&
AuthApplicationComponent::GetAuthenticationService() noexcept {
  return impl_->authentication_service;
}

services::usecases::IdentityService&
AuthApplicationComponent::GetIdentityService() noexcept {
  return impl_->identity_service;
}

services::usecases::PasswordService&
AuthApplicationComponent::GetPasswordService() noexcept {
  return impl_->password_service;
}

services::usecases::SessionService&
AuthApplicationComponent::GetSessionService() noexcept {
  return impl_->session_service;
}

}  // namespace smirkly::auth::components
