#include <utility>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/cluster_types.hpp>
#include <userver/storages/postgres/io/chrono.hpp>

#include <auth/infra/db/pg/repositories/postgres_session_repository.hpp>
#include <auth/infra/db/pg/transactions/pg_transaction.hpp>
#include <auth/infra/db/pg/transactions/pg_tx_cast.hpp>
#include <smirkly::auth/sql_queries.hpp>


namespace smirkly::auth::infra::db::pg {
    PostgresSessionRepository::PostgresSessionRepository(
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster)
        : pg_cluster_(std::move(pg_cluster)) {
    }

    domain::models::Session PostgresSessionRepository::Insert(
        services::ports::DbTransaction &tx,
        const services::ports::NewSessionData &data) {
        return domain::models::Session{};
    }

    std::optional<domain::models::Session>
    PostgresSessionRepository::FindById(std::string_view session_id) {
        return std::nullopt;
    }

    void PostgresSessionRepository::Revoke(
        services::ports::DbTransaction &tx,
        std::string_view session_id
    ) {
        return;
    }

    void PostgresSessionRepository::UpdateLastUsed(
        services::ports::DbTransaction &tx,
        std::string_view session_id,
        std::chrono::system_clock::time_point last_used_at
    ) {
        return;
    }
}
