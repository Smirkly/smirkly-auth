#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <auth/services/ports/uow/db_transaction.hpp>

namespace smirkly::auth::services::ports {
    struct NewEmailVerificationData {
        std::string user_id;
        std::string code_hash;
        std::chrono::system_clock::time_point expires_at;
        std::optional<std::string> ip;
        std::optional<std::string> user_agent;
    };

    struct EmailVerification {
        std::string id;
        std::string user_id;
        std::string code_hash;
        std::chrono::system_clock::time_point expires_at;
        std::optional<std::chrono::system_clock::time_point> used_at;
        std::int32_t attempts{0};
    };

    class EmailVerificationRepository {
    public:
        virtual ~EmailVerificationRepository() = default;

        virtual EmailVerification Insert(
            DbTransaction &tx,
            const NewEmailVerificationData &data) = 0;

        virtual std::optional<EmailVerification> FindActiveByUserId(
            std::string_view user_id,
            std::chrono::system_clock::time_point now) = 0;

        virtual void MarkUsed(
            DbTransaction &tx,
            std::string_view user_id,
            std::chrono::system_clock::time_point) = 0;

        virtual void IncrementAttempts(
            DbTransaction &tx,
            std::string_view verification_id,
            std::chrono::system_clock::time_point now) = 0;
    };
}
