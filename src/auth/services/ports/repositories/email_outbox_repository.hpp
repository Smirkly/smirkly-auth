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
        std::string locale{"ru"};
    };

    struct EmailOutboxEntry {
        std::int64_t id{0};

        std::string to_email;
        std::string code;
        std::string correlation_id;
        std::string locale{"ru"};

        std::size_t attempt{0};
    };

    class EmailOutboxRepository {
    public:
        virtual ~EmailOutboxRepository() = default;

        virtual void Insert(DbTransaction &tx, const EnqueueVerificationEmail &msg) = 0;

        virtual void Insert(const EnqueueVerificationEmail &msg) = 0;

        virtual std::vector<EmailOutboxEntry> ClaimBatch(
            DbTransaction &tx,
            std::size_t next_attempt,
            std::chrono::system_clock::time_point now,
            std::chrono::seconds stuck_timeout,
            std::size_t max_attempts
        ) = 0;

        virtual void MarkSent(
            DbTransaction &tx,
            std::int64_t id,
            std::chrono::system_clock::time_point now,
            std::string_view last_error = {}
        ) = 0;

        virtual void Reschedule(
            DbTransaction &tx,
            std::int64_t id,
            std::size_t next_attempt,
            std::chrono::system_clock::time_point next_at,
            std::string_view last_error
        ) = 0;

        virtual void MarkDead(
            DbTransaction &tx,
            std::int64_t id,
            std::chrono::system_clock::time_point now,
            std::string_view last_error
        ) = 0;
    };
}
