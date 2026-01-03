#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <auth/services/ports/uow/db_transaction.hpp>

namespace smirkly::auth::services::ports {
    struct EnqueueVerificationEmail {
        std::string to_email;
        std::string code;
        std::string correlation_id;
        std::string locale{"ru"};
    };

    class EmailOutboxRepository {
    public:
        virtual ~EmailOutboxRepository() = default;

        virtual void Insert(DbTransaction &tx, const EnqueueVerificationEmail &msg) = 0;

        virtual void Insert(const EnqueueVerificationEmail &msg) = 0;
    };
}
