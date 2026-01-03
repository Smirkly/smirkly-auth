#pragma once

#include <optional>
#include <string>

#include <auth/domain/models/user.hpp>

namespace smirkly::auth::services {
    struct SignUpCommand {
        std::string username;
        std::string password;
        std::optional<std::string> phone;
        std::optional<std::string> email;
    };

    struct SignUpResult {
        domain::models::User user;
    };
}
