#pragma once

#include <userver/components/loggable_component_base.hpp>

#include <auth/services/auth_service.hpp>

namespace smirkly::auth::components {
    class AuthServiceComponent final : public userver::components::LoggableComponentBase {
    public:
        static constexpr std::string_view kName = "auth-service";

        AuthServiceComponent(const userver::components::ComponentConfig &cfg,
                             const userver::components::ComponentContext &ctx);

        static userver::yaml_config::Schema GetStaticConfigSchema();

        domain::services::AuthService &GetService() noexcept;

        const domain::services::AuthService &GetService() const noexcept;

    private:
        domain::services::AuthService auth_service_;
    };
}
