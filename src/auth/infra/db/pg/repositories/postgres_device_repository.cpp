#include <utility>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/cluster_types.hpp>

#include <auth/infra/db/pg/mappers/device_mapper.hpp>
#include <auth/infra/db/pg/repositories/postgres_device_repository.hpp>
#include <auth/infra/db/pg/transactions/pg_transaction.hpp>
#include <auth/infra/db/pg/transactions/pg_tx_cast.hpp>
#include <auth/infra/db/pg/types/device_pg.hpp>
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
        auto &pg_tx = AsPgTx(tx, "PostgresDeviceRepository::Insert");

        const auto res = pg_tx.Native().Execute(
            sql::kDevicesInsert,
            data.user_id,
            std::string(mappers::ToPg(data.device_type)),
            data.device_name,
            data.os_version,
            data.app_version,
            data.fingerprint
        );

        const auto row = res.AsSingleRow<types::DevicePg>(userver::storages::postgres::kRowTag);
        return mappers::ToDomain(row);
    }

    std::optional<domain::models::Device> PostgresDeviceRepository::FindById(std::string_view device_id) {
        const auto res = pg_cluster_->Execute(
            userver::storages::postgres::ClusterHostType::kSlave,
            sql::kDevicesSelectById,
            device_id
        );

        if (res.IsEmpty()) {
            return std::nullopt;
        }

        const auto row = res.AsSingleRow<types::DevicePg>(userver::storages::postgres::kRowTag);
        return mappers::ToDomain(row);
    }
}
