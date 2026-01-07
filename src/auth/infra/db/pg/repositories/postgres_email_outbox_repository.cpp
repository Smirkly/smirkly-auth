#include <auth/infra/db/pg/repositories/postgres_email_outbox_repository.hpp>

#include <utility>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/cluster_types.hpp>

#include <auth/infra/db/pg/transactions/pg_transaction.hpp>
#include <auth/infra/db/pg/transactions/pg_tx_cast.hpp>
#include <smirkly::auth/sql_queries.hpp>


namespace smirkly::auth::infra::db::pg {
    PostgresEmailOutboxRepository::PostgresEmailOutboxRepository(
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster)
        : pg_cluster_(std::move(pg_cluster)) {
    }

    void PostgresEmailOutboxRepository::Insert(services::ports::DbTransaction &tx,
                                               const services::ports::EnqueueVerificationEmail &job) {
        auto &pg_tx = AsPgTx(tx, "PostgresEmailOutboxRepository::Insert");

        pg_tx.Native().Execute(
            sql::kEmailOutboxInsert,
            job.to_email,
            job.code,
            job.locale,
            job.correlation_id
        );
    }

    void PostgresEmailOutboxRepository::Insert(const services::ports::EnqueueVerificationEmail &job) {
        auto tx = PgTransaction::Begin(
            pg_cluster_,
            "PostgresEmailOutboxRepository::Insert.AutoTx"
        );

        PostgresEmailOutboxRepository::Insert(tx, job);

        tx.Commit();
    }
}
