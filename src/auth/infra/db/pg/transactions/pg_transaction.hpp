#pragma once

#include <memory>

#include <auth/services/ports/uow/db_transaction.hpp>

USERVER_NAMESPACE_BEGIN
    namespace storages::postgres {
        class Transaction;
    }

USERVER_NAMESPACE_END

namespace smirkly::auth::infra::db::pg {
    class PgTransactionManager;

    class PgTransaction final : public ::smirkly::auth::services::ports::DbTransaction {
        friend class PgTransactionManager;

        explicit PgTransaction(std::unique_ptr<USERVER_NAMESPACE::storages::postgres::Transaction> tx);

    public:
        PgTransaction(const PgTransaction &) = delete;

        PgTransaction &operator=(const PgTransaction &) = delete;

        ~PgTransaction() noexcept override;

        void Commit() override;

        USERVER_NAMESPACE::storages::postgres::Transaction &Native() noexcept;

    private:
        std::unique_ptr<USERVER_NAMESPACE::storages::postgres::Transaction> tx_;
        bool committed_;
    };
}
