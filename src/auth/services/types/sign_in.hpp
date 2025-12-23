#pragma once

#include <optional>
#include <string>

#include <auth/domain/models/user.hpp>
#include <auth/services/types/auth_tokens.hpp>

namespace smirkly::auth::services {
    struct SignInCommand {
        std::optional<std::string> username;
        std::optional<std::string> email;
        std::optional<std::string> phone;
        std::string password;
    };

    struct SignInResult {
        domain::models::User user;
        AuthTokens tokens;
    };
}
