#pragma once

#include <memory>
#include <string_view>

#include <auth/services/ports/db_transaction.hpp>

namespace smirkly::auth::services::ports {
    class TransactionManager {
    public:
        virtual ~TransactionManager() = default;

        virtual std::unique_ptr<DbTransaction> Begin(std::string_view tx_name) = 0;
    };
}
