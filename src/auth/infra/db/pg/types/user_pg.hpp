#pragma once

#include <chrono>
#include <optional>
#include <string>

#include <auth/domain/models/user.hpp>

namespace smirkly::auth::infra::db::pg::types {
    struct UserPg {
        std::string id;
        std::string username;
        std::optional<std::string> email;
        std::optional<std::string> phone;
        std::string password_hash;
        bool is_email_verified;
        bool is_phone_verified;
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point password_updated_at;
        std::optional<std::chrono::system_clock::time_point> deleted_at;
    };
}
