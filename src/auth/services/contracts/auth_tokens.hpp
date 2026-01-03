#pragma once

#include <string>

namespace smirkly::auth::services {
    struct AuthTokens {
        std::string access_token;
        std::string refresh_token;
    };
}
