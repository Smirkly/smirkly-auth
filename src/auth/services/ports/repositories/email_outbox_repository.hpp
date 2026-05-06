#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <auth/services/ports/uow/db_transaction.hpp>

namespace smirkly::auth::services::ports {
    struct EnqueueVerificationEmail {
        std::string to_email;
        std::string code;
        std::string correlation_id;
        std::string locale;
    };

    struct EmailOutboxEntry {
        std::string id;
        std::string to_email;
        std::string code;
        std::string template_name;
        std::string payload_json;
        std::string correlation_id;
        std::int32_t attempts{0};
        std::chrono::system_clock::time_point next_attempt_at{};
    };

    class EmailOutboxRepository {
    public:
        virtual ~EmailOutboxRepository() = default;

        virtual void Insert(DbTransaction &tx, const EnqueueVerificationEmail &msg) = 0;

        virtual void Insert(const EnqueueVerificationEmail &msg) = 0;

        virtual std::vector<EmailOutboxEntry> ClaimBatch(
            DbTransaction &tx,
            std::size_t batch_size,
            std::chrono::system_clock::time_point now,
            std::chrono::seconds stuck_timeout,
            std::size_t max_attempts
        ) = 0;

        virtual void MarkSent(
            DbTransaction &tx,
            std::string_view id,
            std::chrono::system_clock::time_point now,
            std::string_view last_error = {}
        ) = 0;

        virtual void Reschedule(
            DbTransaction &tx,
            std::string_view id,
            std::chrono::system_clock::time_point next_at,
            std::string_view last_error
        ) = 0;

        virtual void MarkDead(
            DbTransaction &tx,
            std::string_view id,
            std::chrono::system_clock::time_point now,
            std::string_view last_error
        ) = 0;
    };
}
