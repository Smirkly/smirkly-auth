#include <auth/config/auth_http_config.hpp>

#include <string>
#include <utility>
#include <vector>

namespace smirkly::auth::config {

infra::http::ClientIpExtractorConfig ParseClientIpExtractorConfig(
    const userver::components::ComponentConfig& cfg) {
  auto trusted_proxy_cidrs = cfg["trusted-proxy-cidrs"].As<std::vector<std::string>>(
      std::vector<std::string>{"127.0.0.1/32", "::1/128"});

  return infra::http::ClientIpExtractorConfig{
      .trusted_proxy_cidrs = std::move(trusted_proxy_cidrs)};
}

}  // namespace smirkly::auth::config
