#pragma once

#include <optional>
#include <string>

namespace smirkly::auth::domain::models {
    struct User {
        std::string id;
        std::string username;
        std::string password;
        std::optional<std::string> phone;
        std::optional<std::string> email;

        bool is_email_verified = false;
        bool is_phone_verified = false;
    };
}
