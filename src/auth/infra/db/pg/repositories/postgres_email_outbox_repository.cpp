#include <auth/infra/db/pg/repositories/postgres_email_outbox_repository.hpp>

#include <utility>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/cluster_types.hpp>

#include <auth/infra/db/pg/transactions/pg_transaction.hpp>
#include <auth/infra/db/pg/transactions/pg_tx_cast.hpp>
#include <smirkly::auth/sql_queries.hpp>


namespace smirkly::auth::infra::db::pg {
    namespace {
        template<typename ExecFn>
        void InsertOutboxImpl(ExecFn &&exec, const services::ports::EnqueueVerificationEmail &job) {
            exec(job.to_email, job.code, job.locale, job.correlation_id);
        }
    }

    PostgresEmailOutboxRepository::PostgresEmailOutboxRepository(
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster)
        : pg_cluster_(std::move(pg_cluster)) {
    }

    void PostgresEmailOutboxRepository::Insert(services::ports::DbTransaction &tx,
                                               const services::ports::EnqueueVerificationEmail &job) {
        auto &pg_tx = AsPgTx(tx, "PostgresEmailOutboxRepository::Insert");

        InsertOutboxImpl(
            [&](auto &&... args) {
                pg_tx.Native().Execute(sql::kInsertEmailOutbox,
                                       std::forward<decltype(args)>(args)...);
            },
            job
        );
    }

    void PostgresEmailOutboxRepository::Insert(const services::ports::EnqueueVerificationEmail &job) {
        InsertOutboxImpl(
            [&](auto &&... args) {
                pg_cluster_->Execute(
                    userver::storages::postgres::ClusterHostType::kMaster,
                    sql::kInsertEmailOutbox,
                    std::forward<decltype(args)>(args)...
                );
            },
            job
        );
    }
}
