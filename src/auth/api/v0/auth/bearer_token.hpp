#pragma once

#include <optional>
#include <string>

#include <userver/server/http/http_request.hpp>

namespace smirkly::auth::api::v0::auth {
    [[nodiscard]] std::optional<std::string> ExtractBearerToken(
        const userver::server::http::HttpRequest &request
    );
}
