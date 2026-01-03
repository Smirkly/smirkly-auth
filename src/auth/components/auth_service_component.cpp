#include <auth/components/auth_service_component.hpp>

#include <userver/components/component_context.hpp>
#include <userver/storages/postgres/component.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

#include <auth/infra/db/pg/repositories/postgres_email_outbox_repository.hpp>
#include <auth/infra/db/pg/repositories/postgres_user_repository.hpp>
#include <auth/infra/providers/email/log_email_verification_sender.hpp>
#include <auth/infra/security/bcrypt_password_hasher.hpp>
#include <auth/infra/security/random_verification_code_generator.hpp>
#include <auth/services/usecases/auth_service.hpp>

namespace smirkly::auth::components {
    struct AuthServiceComponent::Impl {
        infra::db::pg::PostgresEmailOutboxRepository email_outbox_repo;
        infra::db::pg::PostgresUserRepository user_repo;
        infra::providers::email::EmailVerificationSender email_sender;
        infra::security::BcryptPasswordHasher password_hasher;
        infra::security::RandomVerificationCodeGenerator code_generator;
        services::usecases::AuthService auth_service;

        Impl(const userver::components::ComponentContext &ctx)
            : email_outbox_repo(ctx.FindComponent<userver::components::Postgres>("postgres-auth").GetCluster())
              , user_repo(ctx.FindComponent<userver::components::Postgres>("postgres-auth").GetCluster())
              , email_sender()
              , password_hasher()
              , code_generator(6)
              , auth_service(user_repo, password_hasher, email_sender, code_generator, email_outbox_repo) {
        }
    };

    AuthServiceComponent::AuthServiceComponent(
        const userver::components::ComponentConfig &cfg,
        const userver::components::ComponentContext &ctx)
        : userver::components::LoggableComponentBase(cfg, ctx),
          impl_(std::make_unique<Impl>(ctx)) {
    }

    AuthServiceComponent::~AuthServiceComponent() = default;

    userver::yaml_config::Schema AuthServiceComponent::GetStaticConfigSchema() {
        using userver::yaml_config::MergeSchemas;
        using userver::components::LoggableComponentBase;

        return MergeSchemas<LoggableComponentBase>(R"(
type: object
description: Auth service component config
additionalProperties: false
properties: {}
)");
    }

    services::usecases::AuthService &AuthServiceComponent::GetAuthService() noexcept {
        return impl_->auth_service;
    }

    const services::usecases::AuthService &AuthServiceComponent::GetAuthService() const noexcept {
        return impl_->auth_service;
    }
}
