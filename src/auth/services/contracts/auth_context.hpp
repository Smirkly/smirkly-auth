#pragma once

#include <string>
#include <vector>

#include <auth/domain/models/session.hpp>
#include <auth/domain/models/user.hpp>

namespace smirkly::auth::services::contracts {
    struct AuthContext final {
        std::string user_id;
        std::string session_id;
    };

    struct MeResult final {
        domain::models::User user;
        std::string session_id;
    };

    struct SessionsResult final {
        std::vector<domain::models::Session> sessions;
    };
}
