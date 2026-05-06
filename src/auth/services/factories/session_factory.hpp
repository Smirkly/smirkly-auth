#pragma once

#include <chrono>
#include <string>

#include <auth/services/contracts/request_meta.hpp>
#include <auth/services/ports/repositories/session_repository.hpp>

namespace smirkly::auth::services::factories {
    class SessionFactory final {
    public:
        [[nodiscard]] static ports::NewSessionData CreateForSignIn(
            std::string session_id,
            std::string user_id,
            std::string device_id,
            std::string refresh_token_hash,
            std::string token_family_id,
            const contracts::RequestMeta &meta
        );
    };
}
