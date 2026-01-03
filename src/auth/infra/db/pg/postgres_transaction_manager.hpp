#pragma once

#include <memory>

#include <auth/services/ports/db_transaction.hpp>
#include <auth/services/ports/transaction_manager.hpp>

USERVER_NAMESPACE_BEGIN
    namespace storages::postgres {
        class Cluster;
        using ClusterPtr = std::shared_ptr<Cluster>;
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

    class PgTransactionManager final : public services::ports::TransactionManager {
    public:
        explicit PgTransactionManager(USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster);

        std::unique_ptr<services::ports::DbTransaction> Begin(std::string_view tx_name) override;

    private:
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster_;
    };
}
