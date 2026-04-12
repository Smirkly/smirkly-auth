#include <auth/components/auth_service_component.hpp>

#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

#include <auth/components/auth_infra_component.hpp>
#include <auth/infra/security/password/bcrypt_password_hasher.hpp>
#include <auth/infra/security/verification/random_verification_code_generator.hpp>
#include <auth/services/usecases/auth_service.hpp>

namespace smirkly::auth::components {
    struct AuthServiceComponent::Impl {
        AuthInfraComponent &infra;

        services::ports::TransactionManager &tx_manager;
        services::ports::UserRepository &user_repo;
        services::ports::EmailOutboxRepository &outbox_repo;
        services::ports::EmailVerificationRepository &outbox_verification_repo;

        infra::security::BcryptPasswordHasher password_hasher;
        infra::security::RandomVerificationCodeGenerator code_generator;
        services::usecases::AuthService auth_service;

        Impl(const userver::components::ComponentConfig &cfg,
             const userver::components::ComponentContext &ctx)
            : infra(ctx.FindComponent<AuthInfraComponent>(AuthInfraComponent::kName))
              , tx_manager(infra.GetTransactionManager())
              , user_repo(infra.GetUserRepository())
              , outbox_repo(infra.GetEmailOutboxRepository())
              , outbox_verification_repo(infra.GetEmailVerificationRepository())
              , password_hasher()
              , code_generator(6)
              , auth_service(
                  tx_manager,
                  user_repo,
                  outbox_repo,
                  outbox_verification_repo,
                  password_hasher,
                  code_generator
              ) {
        }
    };

    AuthServiceComponent::AuthServiceComponent(
        const userver::components::ComponentConfig &cfg,
        const userver::components::ComponentContext &ctx)
        : userver::components::LoggableComponentBase(cfg, ctx),
          impl_(std::make_unique<Impl>(cfg, ctx)) {
    }

    AuthServiceComponent::~AuthServiceComponent() = default;


    userver::yaml_config::Schema AuthServiceComponent::GetStaticConfigSchema() {
        using userver::yaml_config::MergeSchemas;
        using userver::components::LoggableComponentBase;

        return MergeSchemas<LoggableComponentBase>(R"(
type: object
description: Auth service component config
additionalProperties: false
properties:
  verification_code_length:
    type: integer
    description: Verification code length
    default: 6
)");
    }


    services::usecases::AuthService &AuthServiceComponent::GetAuthService() noexcept {
        return impl_->auth_service;
    }

    const services::usecases::AuthService &AuthServiceComponent::GetAuthService() const noexcept {
        return impl_->auth_service;
    }
}
