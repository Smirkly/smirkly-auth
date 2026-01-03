#include <auth/infra/db/pg/transactions/pg_tx_cast.hpp>

#include <string>

namespace smirkly::auth::infra::db::pg {
    PgTransaction &AsPgTx(services::ports::DbTransaction &tx, std::string_view where) {
        auto *pg_tx = dynamic_cast<PgTransaction *>(&tx);
        if (!pg_tx) {
            throw std::logic_error(
                std::string(where) + ": tx is not PgTransaction"
            );
        }
        return *pg_tx;
    }

    const PgTransaction &AsPgTx(const services::ports::DbTransaction &tx, std::string_view where) {
        auto *pg_tx = dynamic_cast<const PgTransaction *>(&tx);
        if (!pg_tx) {
            throw std::logic_error(
                std::string(where) + ": tx is not PgTransaction"
            );
        }
        return *pg_tx;
    }
}
