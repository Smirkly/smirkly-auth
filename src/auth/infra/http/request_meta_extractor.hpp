#pragma once

#include <optional>
#include <memory>
#include <string>
#include <vector>

#include <userver/server/http/http_request.hpp>

#include <auth/services/contracts/request_meta.hpp>

namespace smirkly::auth::infra::http {
    struct ClientIpExtractorConfig final {
        std::vector<std::string> trusted_proxy_cidrs;
    };

    class ClientIpExtractor final {
    public:
        explicit ClientIpExtractor(ClientIpExtractorConfig config);

        ~ClientIpExtractor();

        ClientIpExtractor(ClientIpExtractor &&) noexcept;

        ClientIpExtractor &operator=(ClientIpExtractor &&) noexcept;

        ClientIpExtractor(const ClientIpExtractor &) = delete;

        ClientIpExtractor &operator=(const ClientIpExtractor &) = delete;

        [[nodiscard]] std::optional<std::string> Extract(
            const userver::server::http::HttpRequest &request
        ) const;

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };

    class RequestMetaExtractor final {
    public:
        explicit RequestMetaExtractor(ClientIpExtractorConfig config);

        [[nodiscard]] services::contracts::RequestMeta Extract(
            const userver::server::http::HttpRequest &request
        ) const;

    private:
        ClientIpExtractor client_ip_extractor_;
    };
}
