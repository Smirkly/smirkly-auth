#include <auth/services/factories/device_factory.hpp>

#include <utility>

namespace smirkly::auth::services::factories {
    ports::NewDeviceData DeviceFactory::WebDevice(
        std::string user_id,
        const contracts::RequestMeta &meta
    ) {
        return ports::NewDeviceData{
            .user_id = std::move(user_id),
            .device_type = domain::models::DeviceType::kWeb,
            .device_name = std::nullopt,
            .os_version = std::nullopt,
            .app_version = std::nullopt,
            .fingerprint = std::nullopt,
        };
    }
}
