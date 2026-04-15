#pragma once

#include <string>

namespace smirkly::auth::services::contracts {
    struct AuthTokens final {
        std::string access_token;
        std::string refresh_token;
    };
}
