#include <auth/components/auth_service_component.hpp>

#include <userver/yaml_config/merge_schemas.hpp>

namespace smirkly::auth::components {
    AuthServiceComponent::AuthServiceComponent(
        const userver::components::ComponentConfig &cfg,
        const userver::components::ComponentContext &ctx)
        : userver::components::LoggableComponentBase(cfg, ctx) {
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

    domain::services::AuthService &AuthServiceComponent::GetService() noexcept { return auth_service_; }

    const domain::services::AuthService &AuthServiceComponent::GetService() const noexcept { return auth_service_; }
}
