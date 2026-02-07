#pragma once

#include <memory>
#include <string_view>

#include <userver/components/loggable_component_base.hpp>
#include <userver/yaml_config/schema.hpp>

namespace smirkly::auth::services::ports {
    class EmailOutboxRepository;
    class UserRepository;
    class TransactionManager;
}

namespace smirkly::auth::components {
    class AuthInfraComponent final : public userver::components::LoggableComponentBase {
    public:
        static constexpr std::string_view kName = "auth-infra";

        AuthInfraComponent(const userver::components::ComponentConfig &cfg,
                           const userver::components::ComponentContext &ctx);

        ~AuthInfraComponent() override;

        static userver::yaml_config::Schema GetStaticConfigSchema();


        services::ports::UserRepository &GetUserRepository() noexcept;

        const services::ports::UserRepository &GetUserRepository() const noexcept;


        services::ports::EmailOutboxRepository &GetEmailOutboxRepository() noexcept;

        const services::ports::EmailOutboxRepository &GetEmailOutboxRepository() const noexcept;


        services::ports::TransactionManager &GetTransactionManager() noexcept;

        const services::ports::TransactionManager &GetTransactionManager() const noexcept;

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };
}
