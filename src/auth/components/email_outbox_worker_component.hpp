#pragma once

#include <memory>
#include <string_view>

#include <userver/components/loggable_component_base.hpp>
#include <userver/yaml_config/schema.hpp>

namespace smirkly::auth::components {
    class EmailOutboxWorkerComponent final : public userver::components::LoggableComponentBase {
    public:
        static constexpr std::string_view kName = "email-outbox-worker";

        EmailOutboxWorkerComponent(const userver::components::ComponentConfig &cfg,
                                   const userver::components::ComponentContext &ctx);

        ~EmailOutboxWorkerComponent() override;

        void OnAllComponentsLoaded() override;

        void OnAllComponentsAreStopping() override;

        static userver::yaml_config::Schema GetStaticConfigSchema();

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };
} // namespace smirkly::auth::components
