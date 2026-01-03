#pragma once

#include <string_view>

#include <auth/services/ports/uow/db_transaction.hpp>

namespace smirkly::auth::infra::db::pg {
    class PgTransaction;

    PgTransaction &AsPgTx(services::ports::DbTransaction &tx, std::string_view where);

    const PgTransaction &AsPgTx(const services::ports::DbTransaction &tx, std::string_view where);
}
