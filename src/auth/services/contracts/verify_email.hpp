#pragma once

#include <string>

namespace smirkly::auth::services::contracts {
    struct VerifyEmailCommand final {
        std::string email;
        std::string code;
    };

    struct ResendEmailVerificationCommand final {
        std::string email;
    };
}
