#pragma once

#include <string>
#include <optional>

#include "auth/domain/models/user.hpp"

namespace smirkly::auth::domain {
    struct SignUpCommand {
        std::string username;
        std::string password;
        std::optional<std::string> phone;
        std::optional<std::string> email;
    };

    struct AuthTokens {
        std::string access_token;
        std::string refresh_token;
    };

    struct AuthResult {
        models::User user;
        AuthTokens tokens;
    };
}
