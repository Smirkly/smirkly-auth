#include <utility>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/cluster_types.hpp>
#include <userver/storages/postgres/io/chrono.hpp>

#include <auth/infra/db/pg/repositories/postgres_device_repository.hpp>
#include <auth/infra/db/pg/transactions/pg_transaction.hpp>
#include <auth/infra/db/pg/transactions/pg_tx_cast.hpp>
#include <smirkly::auth/sql_queries.hpp>


namespace smirkly::auth::infra::db::pg {
    PostgresDeviceRepository::PostgresDeviceRepository(
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster)
        : pg_cluster_(std::move(pg_cluster)) {
    }

    domain::models::Device PostgresDeviceRepository::Insert(
        services::ports::DbTransaction &tx,
        const services::ports::NewDeviceData &data
    ) {
        return domain::models::Device{};
    }

    std::optional<domain::models::Device> PostgresDeviceRepository::FindById(std::string_view device_id) {
        return std::nullopt;
    }
}
