#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <auth/domain/models/device.hpp>
#include <auth/services/ports/uow/db_transaction.hpp>

namespace smirkly::auth::services::ports {
    struct NewDeviceData final {
        std::string user_id;
        domain::models::DeviceType device_type;
        std::optional<std::string> device_name;
        std::optional<std::string> os_version;
        std::optional<std::string> app_version;
        std::optional<std::string> fingerprint;
    };

    class DeviceRepository {
    public:
        virtual ~DeviceRepository() = default;

        virtual domain::models::Device Insert(
            DbTransaction &tx,
            const NewDeviceData &data
        ) = 0;

        virtual std::optional<domain::models::Device> FindById(std::string_view device_id) = 0;
    };
}
