#include <auth/infra/db/pg/transactions/pg_transaction.hpp>

#include <stdexcept>

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
}
