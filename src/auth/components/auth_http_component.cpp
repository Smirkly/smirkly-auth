#include <auth/components/auth_http_component.hpp>

#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

#include <auth/infra/http/request_meta_extractor.hpp>

namespace smirkly::auth::components {
namespace {
    infra::http::ClientIpExtractorConfig ParseClientIpConfig(
        const userver::components::ComponentConfig &cfg
    ) {
        auto trusted_proxy_cidrs = cfg["trusted-proxy-cidrs"].As<std::vector<std::string>>(
            std::vector<std::string>{"127.0.0.1/32", "::1/128"}
        );

        return infra::http::ClientIpExtractorConfig{
            .trusted_proxy_cidrs = std::move(trusted_proxy_cidrs)
        };
    }
}

    struct AuthHttpComponent::Impl final {
        infra::http::RequestMetaExtractor request_meta_extractor;

        explicit Impl(const userver::components::ComponentConfig &cfg)
            : request_meta_extractor(ParseClientIpConfig(cfg)) {
        }
    };

    AuthHttpComponent::AuthHttpComponent(
        const userver::components::ComponentConfig &cfg,
        const userver::components::ComponentContext &ctx
    )
        : userver::components::LoggableComponentBase(cfg, ctx),
          impl_(std::make_unique<Impl>(cfg)) {
    }

    AuthHttpComponent::~AuthHttpComponent() = default;

    userver::yaml_config::Schema AuthHttpComponent::GetStaticConfigSchema() {
        using userver::components::LoggableComponentBase;
        using userver::yaml_config::MergeSchemas;

        return MergeSchemas<LoggableComponentBase>(R"(
type: object
description: Auth HTTP request metadata extraction config
additionalProperties: false
properties:
  trusted-proxy-cidrs:
    type: array
    description: CIDR ranges whose X-Forwarded-For and X-Real-IP headers are trusted
    default:
      - 127.0.0.1/32
      - ::1/128
    items:
      type: string
      description: Trusted proxy CIDR range
)");
    }

    infra::http::RequestMetaExtractor &AuthHttpComponent::GetRequestMetaExtractor() noexcept {
        return impl_->request_meta_extractor;
    }

    const infra::http::RequestMetaExtractor &AuthHttpComponent::GetRequestMetaExtractor() const noexcept {
        return impl_->request_meta_extractor;
    }
}
