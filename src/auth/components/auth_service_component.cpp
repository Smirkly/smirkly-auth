#include <auth/components/auth_service_component.hpp>

#include <userver/components/component_context.hpp>
#include <userver/storages/postgres/component.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

namespace smirkly::auth::components {
    AuthServiceComponent::AuthServiceComponent(
        const userver::components::ComponentConfig &cfg,
        const userver::components::ComponentContext &ctx)
        : userver::components::LoggableComponentBase(cfg, ctx),
          email_outbox_repo_(
              ctx.FindComponent<userver::components::Postgres>("postgres-auth").GetCluster()
          ),
          user_repo_(
              ctx.FindComponent<userver::components::Postgres>("postgres-auth").GetCluster()
          ),
          email_sender_(/* GetLogger() */),
          password_hasher_(),
          code_generator_(6),
          auth_service_(
              user_repo_,
              password_hasher_,
              email_sender_,
              code_generator_,
              email_outbox_repo_
              /* dependences */) {
    }

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

    services::services::AuthService &AuthServiceComponent::GetService() noexcept { return auth_service_; }

    const services::services::AuthService &AuthServiceComponent::GetService() const noexcept { return auth_service_; }
}
