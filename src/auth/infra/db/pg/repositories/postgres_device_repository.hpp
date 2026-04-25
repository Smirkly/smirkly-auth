#pragma once

#include <memory>
#include <optional>
#include <string_view>

#include <auth/services/ports/repositories/device_repository.hpp>

USERVER_NAMESPACE_BEGIN
    namespace storages::postgres {
        class Cluster;
        using ClusterPtr = std::shared_ptr<Cluster>;
    }

USERVER_NAMESPACE_END

namespace smirkly::auth::infra::db::pg {
    class PostgresDeviceRepository final : public services::ports::DeviceRepository {
    public:
        explicit PostgresDeviceRepository(USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster);

        domain::models::Device Insert(
            services::ports::DbTransaction &tx,
            const services::ports::NewDeviceData &data
        ) override;

        std::optional<domain::models::Device> FindById(std::string_view device_id) override;

    private:
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster_;
    };
}
