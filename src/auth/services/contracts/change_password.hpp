#pragma once

#include <string>

namespace smirkly::auth::services::contracts {
    struct ChangePasswordCommand final {
        std::string current_password;
        std::string new_password;
    };
}
