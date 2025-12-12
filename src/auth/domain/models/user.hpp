#pragma once
#include <string>

namespace smirkly::auth::domain::models {
    struct User {
        std::string id;
        std::string username;
        std::string password;
        std::optional<std::string> phone;
        std::optional<std::string> email;
    };
}
