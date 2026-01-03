#include <auth/infra/db/pg/postgres_transaction_manager.hpp>

#include <memory>
#include <stdexcept>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/cluster_types.hpp>
#include <userver/storages/postgres/transaction.hpp>

namespace smirkly::auth::infra::db::pg {
    PgTransaction::PgTransaction(std::unique_ptr<USERVER_NAMESPACE::storages::postgres::Transaction> tx)
        : tx_(std::move(tx)), committed_(false) {
        if (!tx_) throw std::logic_error("PgTransaction: null tx");
    }

    PgTransaction::~PgTransaction() = default;

    void PgTransaction::Commit() {
        if (committed_) {
            throw std::logic_error("Transaction already committed");
        }

        tx_->Commit();
        committed_ = true;
    }

    USERVER_NAMESPACE::storages::postgres::Transaction &PgTransaction::Native() noexcept {
        return *tx_;
    }


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

        auto tx_ptr = std::make_unique<USERVER_NAMESPACE::storages::postgres::Transaction>(std::move(tx));

        return std::unique_ptr<services::ports::DbTransaction>(
            new PgTransaction(std::move(tx_ptr))
        );
    }
}
