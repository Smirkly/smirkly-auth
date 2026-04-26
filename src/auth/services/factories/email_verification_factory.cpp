#include <auth/services/factories/email_verification_factory.hpp>

#include <utility>

namespace smirkly::auth::services::factories {
    ports::NewEmailVerificationData EmailVerificationFactory::Create(
        std::string user_id,
        std::string code_hash,
        const contracts::RequestMeta &meta,
        std::chrono::system_clock::time_point now,
        std::chrono::minutes ttl
    ) {
        return ports::NewEmailVerificationData{
            .user_id = std::move(user_id),
            .code_hash = std::move(code_hash),
            .expires_at = now + ttl,
            .ip = meta.ip,
            .user_agent = meta.user_agent
        };
    }
}
