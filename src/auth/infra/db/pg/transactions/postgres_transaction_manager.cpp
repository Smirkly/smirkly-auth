#include <auth/infra/db/pg/transactions/postgres_transaction_manager.hpp>

#include <stdexcept>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/cluster_types.hpp>
#include <userver/storages/postgres/transaction.hpp>

namespace smirkly::auth::infra::db::pg {
    PgTransactionManager::PgTransactionManager(
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster) : pg_cluster_(std::move(pg_cluster)) {
    }

    std::unique_ptr<services::ports::DbTransaction> PgTransactionManager::Begin(std::string_view tx_name) {
        USERVER_NAMESPACE::storages::postgres::TransactionOptions opts{};
        auto tx = pg_cluster_->Begin(
            std::string{tx_name},
            USERVER_NAMESPACE::storages::postgres::ClusterHostType::kMaster,
            opts
        );

        return std::unique_ptr<services::ports::DbTransaction>(
            new PgTransaction(std::move(tx))
        );
    }
}
