#pragma once

#include <string>

namespace smirkly::auth::services::contracts {
    struct RefreshCommand final {
        std::string refresh_token;
    };

    struct RefreshResult final {
        std::string access_token;
        std::string refresh_token;
        std::string session_id;
    };
}
