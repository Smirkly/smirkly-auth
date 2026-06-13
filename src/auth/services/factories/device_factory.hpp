#pragma once

#include <string>

#include <auth/services/contracts/request_meta.hpp>
#include <auth/services/ports/repositories/device_repository.hpp>

namespace smirkly::auth::services::factories {
    class DeviceFactory final {
    public:
        [[nodiscard]] static ports::NewDeviceData WebDevice(
            std::string user_id,
            const contracts::RequestMeta &
        );
    };
}
