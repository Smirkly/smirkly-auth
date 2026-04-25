#pragma once

#include <optional>
#include <string>

namespace smirkly::auth::services::contracts {
    struct RequestMeta final {
        std::optional<std::string> ip;
        std::optional<std::string> user_agent;
    };
}
