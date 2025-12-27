#include <auth/infra/db/pg/postgres_email_outbox_repository.hpp>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/cluster_types.hpp>

#include <smirkly::auth/sql_queries.hpp>


namespace smirkly::auth::infra::db::pg {
    PostgresEmailOutboxRepository::PostgresEmailOutboxRepository(
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster)
        : pg_cluster_(std::move(pg_cluster)) {
    }


    void PostgresEmailOutboxRepository::Insert(const services::ports::EnqueueVerificationEmail &job) {
        pg_cluster_->Execute(
            userver::storages::postgres::ClusterHostType::kMaster,
            sql::kInsertEmailOutbox,
            job.to_email,
            job.code,
            job.locale,
            job.correlation_id
        );
    }
}
