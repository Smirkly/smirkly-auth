#pragma once

#include <memory>
#include <string_view>

#include <userver/storages/postgres/cluster_types.hpp>
#include <userver/storages/postgres/transaction.hpp>

#include <auth/services/ports/uow/db_transaction.hpp>

namespace smirkly::auth::infra::db::pg {
    class PgTransactionManager;

    class PgTransaction final : public services::ports::DbTransaction {
        friend class PgTransactionManager;

        explicit PgTransaction(USERVER_NAMESPACE::storages::postgres::Transaction tx);

    public:
        PgTransaction(const PgTransaction &) = delete;

        PgTransaction &operator=(const PgTransaction &) = delete;

        PgTransaction(PgTransaction &&) = default;

        PgTransaction &operator=(PgTransaction &&) = default;

        ~PgTransaction() noexcept override;

        void Commit() override;

        USERVER_NAMESPACE::storages::postgres::Transaction &Native() noexcept;

        const USERVER_NAMESPACE::storages::postgres::Transaction &Native() const noexcept;

    public:
        static PgTransaction Begin(
            userver::storages::postgres::ClusterPtr pg_cluster, std::string name,
            userver::storages::postgres::ClusterHostType host_type =
                    userver::storages::postgres::ClusterHostType::kMaster,
            userver::storages::postgres::TransactionOptions options = {}
        );

    private:
        USERVER_NAMESPACE::storages::postgres::Transaction tx_;
        bool committed_;
    };
}
