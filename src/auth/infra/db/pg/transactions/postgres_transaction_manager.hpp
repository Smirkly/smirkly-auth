#pragma once

#include <memory>

#include <auth/infra/db/pg/transactions/pg_transaction.hpp>
#include <auth/services/ports/uow/transaction_manager.hpp>

USERVER_NAMESPACE_BEGIN
    namespace storages::postgres {
        class Cluster;
        using ClusterPtr = std::shared_ptr<Cluster>;
    }

USERVER_NAMESPACE_END

namespace smirkly::auth::infra::db::pg {
    class PgTransactionManager final : public services::ports::TransactionManager {
    public:
        explicit PgTransactionManager(USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster);

        std::unique_ptr<services::ports::DbTransaction> Begin(std::string_view tx_name) override;

    private:
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster_;
    };
}
