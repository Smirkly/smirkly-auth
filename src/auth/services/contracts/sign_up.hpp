#pragma once

#include <optional>
#include <string>

#include <auth/domain/models/user.hpp>

namespace smirkly::auth::services::contracts {
    struct SignUpCommand final {
        std::string username;
        std::string password;
        std::optional<std::string> phone;
        std::optional<std::string> email;
    };

    struct SignUpResult final {
        domain::models::User user;
    };
}
