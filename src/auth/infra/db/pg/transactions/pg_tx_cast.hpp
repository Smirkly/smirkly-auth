#pragma once

#include <string>
#include <string_view>

#include <auth/infra/db/pg/transactions/pg_transaction.hpp>
#include <auth/services/ports/uow/db_transaction.hpp>

namespace smirkly::auth::infra::db::pg {
    class PgTransaction;

    inline PgTransaction &AsPgTx(services::ports::DbTransaction &tx, std::string_view where) {
#ifdef NDEBUG
        auto *pg_tx = dynamic_cast<PgTransaction *>(&tx);
        if (!pg_tx) {
            throw std::logic_error(
                std::string(where) + ": tx is not PgTransaction"
            );
        }
        return *pg_tx;
#else
        return static_cast<PgTransaction &>(tx);
#endif
    }

    inline const PgTransaction &AsPgTx(const services::ports::DbTransaction &tx, std::string_view where) {
#ifdef NDEBUG
        auto *pg_tx = dynamic_cast<const PgTransaction *>(&tx);
        if (!pg_tx) {
            throw std::logic_error(
                std::string(where) + ": tx is not PgTransaction"
            );
        }
        return *pg_tx;
#else
        return static_cast<const PgTransaction &>(tx);
#endif
    }
}
