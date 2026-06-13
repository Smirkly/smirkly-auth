#include <auth/infra/http/request_meta_extractor.hpp>

#include <stdexcept>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <userver/engine/io/sockaddr.hpp>
#include <userver/server/http/http_request_builder.hpp>
#include <userver/utest/utest.hpp>

namespace {
    using smirkly::auth::infra::http::ClientIpExtractorConfig;
    using smirkly::auth::infra::http::RequestMetaExtractor;

    userver::engine::io::Sockaddr MakeSockaddr(const std::string &ip) {
        userver::engine::io::Sockaddr addr;

        if (ip.find(':') == std::string::npos) {
            auto *sa = addr.As<sockaddr_in>();
            sa->sin_family = AF_INET;
            if (::inet_pton(AF_INET, ip.c_str(), &sa->sin_addr) != 1) {
                throw std::runtime_error("invalid IPv4 test address");
            }
            return addr;
        }

        auto *sa = addr.As<sockaddr_in6>();
        sa->sin6_family = AF_INET6;
        if (::inet_pton(AF_INET6, ip.c_str(), &sa->sin6_addr) != 1) {
            throw std::runtime_error("invalid IPv6 test address");
        }
        return addr;
    }

    std::shared_ptr<userver::server::http::HttpRequest> MakeRequest(
        const std::string &remote_ip,
        std::vector<std::pair<std::string, std::string>> headers = {}
    ) {
        userver::server::http::HttpRequestBuilder builder;
        builder.SetRemoteAddress(MakeSockaddr(remote_ip));
        for (auto &[name, value]: headers) {
            builder.AddHeader(std::move(name), std::move(value));
        }
        return builder.Build();
    }

    ClientIpExtractorConfig TrustedLoopbackOnly() {
        return ClientIpExtractorConfig{
            .trusted_proxy_cidrs = {"127.0.0.1/32", "::1/128"}
        };
    }

    void ExpectIp(
        const RequestMetaExtractor &extractor,
        const userver::server::http::HttpRequest &request,
        const std::string &expected
    ) {
        const auto meta = extractor.Extract(request);
        ASSERT_TRUE(meta.ip.has_value());
        EXPECT_EQ(*meta.ip, expected);
    }
}

UTEST(RequestMetaExtractor, UntrustedRemoteIgnoresForwardedHeaders) {
    const RequestMetaExtractor extractor{TrustedLoopbackOnly()};
    const auto request = MakeRequest(
        "198.51.100.9",
        {
            {"X-Forwarded-For", "203.0.113.10"},
            {"X-Real-IP", "203.0.113.11"},
            {"User-Agent", "unit-test"}
        }
    );

    const auto meta = extractor.Extract(*request);

    ASSERT_TRUE(meta.ip.has_value());
    EXPECT_EQ(*meta.ip, "198.51.100.9");
    ASSERT_TRUE(meta.user_agent.has_value());
    EXPECT_EQ(*meta.user_agent, "unit-test");
}

UTEST(RequestMetaExtractor, TrustedProxyUsesRightmostUntrustedForwardedFor) {
    const RequestMetaExtractor extractor{TrustedLoopbackOnly()};
    const auto request = MakeRequest(
        "127.0.0.1",
        {{"X-Forwarded-For", "1.2.3.4, 203.0.113.10"}}
    );

    ExpectIp(extractor, *request, "203.0.113.10");
}

UTEST(RequestMetaExtractor, TrustedProxySkipsKnownProxyChain) {
    const RequestMetaExtractor extractor{
        ClientIpExtractorConfig{
            .trusted_proxy_cidrs = {"127.0.0.1/32", "10.0.0.0/8"}
        }
    };
    const auto request = MakeRequest(
        "127.0.0.1",
        {{"X-Forwarded-For", "203.0.113.10, 10.1.2.3"}}
    );

    ExpectIp(extractor, *request, "203.0.113.10");
}

UTEST(RequestMetaExtractor, MalformedForwardedForFallsBackToRealIp) {
    const RequestMetaExtractor extractor{TrustedLoopbackOnly()};
    const auto request = MakeRequest(
        "127.0.0.1",
        {
            {"X-Forwarded-For", "203.0.113.10, bad-ip"},
            {"X-Real-IP", "203.0.113.11"}
        }
    );

    ExpectIp(extractor, *request, "203.0.113.11");
}

UTEST(RequestMetaExtractor, MalformedForwardedHeadersFallbackToRemote) {
    const RequestMetaExtractor extractor{TrustedLoopbackOnly()};
    const auto request = MakeRequest(
        "127.0.0.1",
        {
            {"X-Forwarded-For", "bad-ip"},
            {"X-Real-IP", "also-bad"}
        }
    );

    ExpectIp(extractor, *request, "127.0.0.1");
}

UTEST(RequestMetaExtractor, SupportsIpv6ForwardedFor) {
    const RequestMetaExtractor extractor{TrustedLoopbackOnly()};
    const auto request = MakeRequest(
        "::1",
        {{"X-Forwarded-For", "2001:db8::10"}}
    );

    ExpectIp(extractor, *request, "2001:db8::10");
}

UTEST(RequestMetaExtractor, InvalidTrustedProxyCidrFailsFast) {
    EXPECT_THROW(
        RequestMetaExtractor(
            ClientIpExtractorConfig{
                .trusted_proxy_cidrs = {"10.0.0.0/33"}
            }
        ),
        std::invalid_argument
    );
}
