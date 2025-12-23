#pragma once

#include <chrono>
#include <optional>
#include <string>

namespace smirkly::auth::domain::models {
    struct Session {
        std::string id;
        std::string user_id;
        std::optional<std::string> device_id;
        std::string refresh_token_hash;
        std::optional<std::string> ip;
        std::optional<std::string> user_agent;
        std::chrono::system_clock::time_point created_at;
        std::optional<std::chrono::system_clock::time_point> last_used_at;
        std::chrono::system_clock::time_point expires_at;
        std::optional<std::chrono::system_clock::time_point> revoked_at;
        bool is_active = false;
    };
}
