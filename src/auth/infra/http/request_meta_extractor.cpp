#include <auth/infra/http/request_meta_extractor.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <utility>

#include <arpa/inet.h>
#include <netinet/in.h>

namespace smirkly::auth::infra::http {
namespace {
    enum class IpVersion {
        kV4,
        kV6,
    };

    struct ParsedIp final {
        IpVersion version;
        std::array<unsigned char, 16> bytes{};
        std::string text;
    };

    struct IpNetwork final {
        IpVersion version;
        std::array<unsigned char, 16> bytes{};
        std::uint8_t prefix_length{};
    };

    std::string_view Trim(std::string_view value) {
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
            value.remove_prefix(1);
        }
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
            value.remove_suffix(1);
        }
        return value;
    }

    std::string InetToString(int family, const void *addr) {
        std::array<char, INET6_ADDRSTRLEN> buffer{};
        if (::inet_ntop(family, addr, buffer.data(), buffer.size()) == nullptr) {
            throw std::runtime_error("inet_ntop failed while normalizing client IP");
        }
        return buffer.data();
    }

    std::optional<ParsedIp> ParseIp(std::string_view raw) {
        raw = Trim(raw);
        if (raw.empty() || raw.find(',') != std::string_view::npos) {
            return std::nullopt;
        }

        const auto value = std::string{raw};

        in_addr ipv4{};
        if (::inet_pton(AF_INET, value.c_str(), &ipv4) == 1) {
            ParsedIp parsed{.version = IpVersion::kV4, .text = InetToString(AF_INET, &ipv4)};
            std::memcpy(parsed.bytes.data(), &ipv4, sizeof(ipv4));
            return parsed;
        }

        in6_addr ipv6{};
        if (::inet_pton(AF_INET6, value.c_str(), &ipv6) == 1) {
            ParsedIp parsed{.version = IpVersion::kV6, .text = InetToString(AF_INET6, &ipv6)};
            std::memcpy(parsed.bytes.data(), &ipv6, sizeof(ipv6));
            return parsed;
        }

        return std::nullopt;
    }

    std::optional<std::uint8_t> ParsePrefixLength(
        std::string_view raw,
        IpVersion version
    ) {
        raw = Trim(raw);
        if (raw.empty()) {
            return std::nullopt;
        }

        unsigned value = 0;
        const auto *begin = raw.data();
        const auto *end = raw.data() + raw.size();
        const auto result = std::from_chars(begin, end, value);
        if (result.ec != std::errc{} || result.ptr != end) {
            return std::nullopt;
        }

        const auto max_prefix = version == IpVersion::kV4 ? 32U : 128U;
        if (value > max_prefix) {
            return std::nullopt;
        }

        return static_cast<std::uint8_t>(value);
    }

    bool PrefixMatches(
        const std::array<unsigned char, 16> &network,
        const std::array<unsigned char, 16> &address,
        std::uint8_t prefix_length
    ) {
        const auto full_bytes = prefix_length / 8;
        const auto remaining_bits = prefix_length % 8;

        for (std::uint8_t i = 0; i < full_bytes; ++i) {
            if (network[i] != address[i]) {
                return false;
            }
        }

        if (remaining_bits == 0) {
            return true;
        }

        const auto mask = static_cast<unsigned char>(0xFFU << (8 - remaining_bits));
        return (network[full_bytes] & mask) == (address[full_bytes] & mask);
    }

    std::optional<std::vector<ParsedIp>> ParseForwardedFor(std::string_view header) {
        if (Trim(header).empty()) {
            return std::nullopt;
        }

        std::vector<ParsedIp> result;
        while (true) {
            const auto comma_pos = header.find(',');
            const auto token = comma_pos == std::string_view::npos
                                   ? header
                                   : header.substr(0, comma_pos);

            auto parsed = ParseIp(token);
            if (!parsed) {
                return std::nullopt;
            }
            result.push_back(std::move(*parsed));

            if (comma_pos == std::string_view::npos) {
                break;
            }
            header.remove_prefix(comma_pos + 1);
        }

        return result;
    }

    IpNetwork ParseTrustedProxyCidr(std::string_view cidr) {
        cidr = Trim(cidr);
        const auto slash_pos = cidr.find('/');

        const auto address_part = slash_pos == std::string_view::npos
                                      ? cidr
                                      : cidr.substr(0, slash_pos);
        auto address = ParseIp(address_part);
        if (!address) {
            throw std::invalid_argument("invalid trusted proxy CIDR address");
        }

        const auto default_prefix = address->version == IpVersion::kV4 ? 32 : 128;
        const auto prefix = slash_pos == std::string_view::npos
                                ? std::optional<std::uint8_t>{
                                      static_cast<std::uint8_t>(default_prefix)
                                  }
                                : ParsePrefixLength(cidr.substr(slash_pos + 1), address->version);

        if (!prefix) {
            throw std::invalid_argument("invalid trusted proxy CIDR prefix length");
        }

        IpNetwork network;
        network.version = address->version;
        network.bytes = address->bytes;
        network.prefix_length = *prefix;
        return network;
    }
}

    struct ClientIpExtractor::Impl final {
        explicit Impl(const ClientIpExtractorConfig &config) {
            trusted_proxies.reserve(config.trusted_proxy_cidrs.size());
            for (const auto &cidr: config.trusted_proxy_cidrs) {
                trusted_proxies.push_back(ParseTrustedProxyCidr(cidr));
            }
        }

        [[nodiscard]] bool IsTrustedProxy(const ParsedIp &address) const {
            return std::any_of(
                trusted_proxies.begin(),
                trusted_proxies.end(),
                [&address](const IpNetwork &network) {
                    return network.version == address.version &&
                           PrefixMatches(network.bytes, address.bytes, network.prefix_length);
                }
            );
        }

        std::vector<IpNetwork> trusted_proxies;
    };

    ClientIpExtractor::ClientIpExtractor(ClientIpExtractorConfig config)
        : impl_(std::make_unique<Impl>(config)) {
    }

    ClientIpExtractor::~ClientIpExtractor() = default;

    ClientIpExtractor::ClientIpExtractor(ClientIpExtractor &&) noexcept = default;

    ClientIpExtractor &ClientIpExtractor::operator=(ClientIpExtractor &&) noexcept = default;

    std::optional<std::string> ClientIpExtractor::Extract(
        const userver::server::http::HttpRequest &request
    ) const {
        auto remote_ip = ParseIp(request.GetRemoteAddress().PrimaryAddressString());
        if (!remote_ip) {
            return std::nullopt;
        }

        if (!impl_->IsTrustedProxy(*remote_ip)) {
            return remote_ip->text;
        }

        if (const auto xff = request.GetHeader("X-Forwarded-For"); !xff.empty()) {
            if (auto chain = ParseForwardedFor(xff); chain && !chain->empty()) {
                chain->push_back(*remote_ip);

                for (auto it = chain->rbegin(); it != chain->rend(); ++it) {
                    if (!impl_->IsTrustedProxy(*it)) {
                        return it->text;
                    }
                }

                return chain->front().text;
            }
        }

        if (const auto xri = request.GetHeader("X-Real-IP"); !xri.empty()) {
            if (auto real_ip = ParseIp(xri)) {
                return real_ip->text;
            }
        }

        return remote_ip->text;
    }

    RequestMetaExtractor::RequestMetaExtractor(ClientIpExtractorConfig config)
        : client_ip_extractor_(std::move(config)) {
    }

    services::contracts::RequestMeta RequestMetaExtractor::Extract(
        const userver::server::http::HttpRequest &request
    ) const {
        services::contracts::RequestMeta meta;
        meta.ip = client_ip_extractor_.Extract(request);

        if (const auto user_agent = request.GetHeader("User-Agent"); !user_agent.empty()) {
            meta.user_agent = std::string{user_agent};
        }

        return meta;
    }
}
