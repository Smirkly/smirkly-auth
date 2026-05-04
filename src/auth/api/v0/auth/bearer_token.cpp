#include <auth/api/v0/auth/bearer_token.hpp>

#include <string_view>

namespace smirkly::auth::api::v0::auth {
    std::optional<std::string> ExtractBearerToken(
        const userver::server::http::HttpRequest &request
    ) {
        constexpr std::string_view kPrefix = "Bearer ";

        const auto authorization = request.GetHeader("Authorization");
        if (authorization.size() <= kPrefix.size()) {
            return std::nullopt;
        }
        if (authorization.substr(0, kPrefix.size()) != kPrefix) {
            return std::nullopt;
        }

        return std::string{authorization.substr(kPrefix.size())};
    }
}
