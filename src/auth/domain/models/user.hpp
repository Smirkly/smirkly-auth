#pragma once

#include <chrono>
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

        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point password_updated_at;
        std::optional<std::chrono::system_clock::time_point> deleted_at;
    };
}
