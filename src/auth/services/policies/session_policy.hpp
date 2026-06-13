#pragma once

#include <chrono>

namespace smirkly::auth::services::policies {
    struct SessionPolicy final {
        std::chrono::seconds refresh_token_ttl{0};
        std::chrono::seconds activity_update_threshold{std::chrono::minutes{5}};
    };
}
