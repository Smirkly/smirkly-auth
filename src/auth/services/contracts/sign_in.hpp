#pragma once

#include <optional>
#include <string>

#include <auth/domain/models/user.hpp>
#include <auth/services/contracts/auth_tokens.hpp>

namespace smirkly::auth::services::contracts {
    struct SignInCommand final {
        std::optional<std::string> username;
        std::optional<std::string> email;
        std::optional<std::string> phone;
        std::string password;
    };

    struct SignInResult final {
        domain::models::User user;
        AuthTokens tokens;
        std::string session_id;
    };
}
