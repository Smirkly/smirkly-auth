#pragma once

#include <memory>
#include <string_view>

#include <userver/components/loggable_component_base.hpp>

namespace smirkly::auth::infra::http {
    class RequestMetaExtractor;
}

namespace smirkly::auth::components {
    class AuthHttpComponent final : public userver::components::LoggableComponentBase {
    public:
        static constexpr std::string_view kName = "auth-http";

        AuthHttpComponent(const userver::components::ComponentConfig &cfg,
                          const userver::components::ComponentContext &ctx);

        ~AuthHttpComponent() override;

        static userver::yaml_config::Schema GetStaticConfigSchema();

        infra::http::RequestMetaExtractor &GetRequestMetaExtractor() noexcept;

        const infra::http::RequestMetaExtractor &GetRequestMetaExtractor() const noexcept;

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };
}
