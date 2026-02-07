#include <auth/components/auth_infra_component.hpp>

#include <string>

#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/storages/postgres/component.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

#include <auth/infra/db/pg/repositories/postgres_email_outbox_repository.hpp>
#include <auth/infra/db/pg/repositories/postgres_user_repository.hpp>
#include <auth/infra/db/pg/transactions/postgres_transaction_manager.hpp>

namespace smirkly::auth::components {
    struct AuthInfraComponent::Impl {
        infra::db::pg::PostgresEmailOutboxRepository email_outbox_repo;
        infra::db::pg::PostgresUserRepository user_repo;
        infra::db::pg::PgTransactionManager transaction_manager;

        Impl(const userver::components::ComponentConfig &cfg,
             const userver::components::ComponentContext &ctx)
            : email_outbox_repo(
                  ctx.FindComponent<userver::components::Postgres>(
                      cfg["postgres-component"].As<std::string>("postgres-auth"))
                  .GetCluster())
              , user_repo(
                  ctx.FindComponent<userver::components::Postgres>(
                      cfg["postgres-component"].As<std::string>("postgres-auth"))
                  .GetCluster())
              , transaction_manager(
                  ctx.FindComponent<userver::components::Postgres>(
                      cfg["postgres-component"].As<std::string>("postgres-auth"))
                  .GetCluster()) {
        }
    };

    AuthInfraComponent::AuthInfraComponent(const userver::components::ComponentConfig &cfg,
                                           const userver::components::ComponentContext &ctx)
        : userver::components::LoggableComponentBase(cfg, ctx)
          , impl_(std::make_unique<Impl>(cfg, ctx)) {
    }

    AuthInfraComponent::~AuthInfraComponent() = default;

    userver::yaml_config::Schema AuthInfraComponent::GetStaticConfigSchema() {
        using userver::yaml_config::MergeSchemas;
        using userver::components::LoggableComponentBase;

        return MergeSchemas<LoggableComponentBase>(R"(
type: object
description: Auth infrastructure (db repos + tx manager)
additionalProperties: false
properties:
  postgres-component:
    type: string
    description: Name of Postgres component to use
    default: postgres-auth
)");
    }

    services::ports::UserRepository &AuthInfraComponent::GetUserRepository() noexcept {
        return impl_->user_repo;
    }

    const services::ports::UserRepository &AuthInfraComponent::GetUserRepository() const noexcept {
        return impl_->user_repo;
    }


    services::ports::EmailOutboxRepository &AuthInfraComponent::GetEmailOutboxRepository() noexcept {
        return impl_->email_outbox_repo;
    }

    const services::ports::EmailOutboxRepository &AuthInfraComponent::GetEmailOutboxRepository() const noexcept {
        return impl_->email_outbox_repo;
    }


    services::ports::TransactionManager &AuthInfraComponent::GetTransactionManager() noexcept {
        return impl_->transaction_manager;
    }

    const services::ports::TransactionManager &AuthInfraComponent::GetTransactionManager() const noexcept {
        return impl_->transaction_manager;
    }
} // namespace smirkly::auth::components
