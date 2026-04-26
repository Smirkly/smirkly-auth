#pragma once

#include <chrono>
#include <string>

#include <auth/services/contracts/request_meta.hpp>
#include <auth/services/ports/repositories/email_verification_repository.hpp>

namespace smirkly::auth::services::factories {
    class EmailVerificationFactory final {
    public:
        [[nodiscard]] static ports::NewEmailVerificationData Create(
            std::string user_id,
            std::string code_hash,
            const contracts::RequestMeta &meta,
            std::chrono::system_clock::time_point now,
            std::chrono::minutes ttl
        );
    };
}
