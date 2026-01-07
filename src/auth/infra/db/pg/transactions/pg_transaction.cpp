#include <auth/infra/db/pg/transactions/pg_transaction.hpp>

#include <stdexcept>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/transaction.hpp>

namespace smirkly::auth::infra::db::pg {
    PgTransaction::PgTransaction(USERVER_NAMESPACE::storages::postgres::Transaction tx)
        : tx_(std::move(tx)), committed_(false) {
    }

    PgTransaction::~PgTransaction() noexcept = default;

    void PgTransaction::Commit() {
        if (committed_) {
            throw std::logic_error("Transaction already committed");
        }

        tx_.Commit();
        committed_ = true;
    }

    USERVER_NAMESPACE::storages::postgres::Transaction &PgTransaction::Native() noexcept {
        return tx_;
    }

    const USERVER_NAMESPACE::storages::postgres::Transaction &PgTransaction::Native() const noexcept {
        return tx_;
    }

    PgTransaction PgTransaction::Begin(
        userver::storages::postgres::ClusterPtr pg_cluster, std::string name,
        userver::storages::postgres::ClusterHostType host_type,
        userver::storages::postgres::TransactionOptions options
    ) {
        return PgTransaction(pg_cluster->Begin(std::move(name), host_type, options)
        );
    }
}
