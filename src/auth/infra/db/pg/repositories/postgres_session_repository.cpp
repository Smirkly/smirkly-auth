#include <utility>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/cluster_types.hpp>
#include <userver/storages/postgres/io/chrono.hpp>

#include <auth/infra/db/pg/mappers/session_mapper.hpp>
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
        auto &pg_tx = AsPgTx(tx, "PostgresSessionRepository::Insert");

        const auto res = pg_tx.Native().Execute(
            sql::kSessionsInsert,
            data.id,
            data.user_id,
            data.device_id,
            data.refresh_token_hash,
            data.ip,
            data.user_agent,
            USERVER_NAMESPACE::storages::postgres::TimePointTz{data.expires_at},
            data.token_family_id,
            data.replaced_by_session_id
        );

        const auto row = res.AsSingleRow<types::SessionPg>(userver::storages::postgres::kRowTag);
        return mappers::ToDomain(row);
    }

    std::optional<domain::models::Session>
    PostgresSessionRepository::FindById(std::string_view session_id) {
        const auto res = pg_cluster_->Execute(
            userver::storages::postgres::ClusterHostType::kSlave,
            sql::kSessionsSelectById,
            session_id
        );

        if (res.IsEmpty()) {
            return std::nullopt;
        }

        const auto row = res.AsSingleRow<types::SessionPg>(userver::storages::postgres::kRowTag);
        return mappers::ToDomain(row);
    }

    void PostgresSessionRepository::Revoke(
        services::ports::DbTransaction &tx,
        std::string_view session_id
    ) {
        auto &pg_tx = AsPgTx(tx, "PostgresSessionRepository::Revoke");

        pg_tx.Native().Execute(
            sql::kSessionsRevoke,
            session_id
        );
    }

    void PostgresSessionRepository::UpdateLastUsed(
        services::ports::DbTransaction &tx,
        std::string_view session_id,
        std::chrono::system_clock::time_point last_used_at
    ) {
        auto &pg_tx = AsPgTx(tx, "PostgresSessionRepository::UpdateLastUsed");

        pg_tx.Native().Execute(
            sql::kSessionsUpdateLastUsed,
            session_id,
            USERVER_NAMESPACE::storages::postgres::TimePointTz{last_used_at}
        );
    }
}
