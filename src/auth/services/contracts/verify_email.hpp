#pragma once

#include <string>

namespace smirkly::auth::services {
    struct VerifyEmailCommand final {
        std::string email;
        std::string code;
    };
}
