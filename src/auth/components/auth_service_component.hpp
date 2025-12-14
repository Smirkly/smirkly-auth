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

        services::services::AuthService &GetService() noexcept;

        const services::services::AuthService &GetService() const noexcept;

    private:
        services::services::AuthService auth_service_;
    };
}
