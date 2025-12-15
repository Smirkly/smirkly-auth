#pragma once

#include <string>
#include <optional>
#include <chrono>

namespace smirkly::auth::domain::models {
    enum class DeviceType {
        kIos,
        kAndroid,
        kWeb,
        kDesktop,
    };

    struct Device {
        std::string id;
        std::string user_id;
        DeviceType device_type;
        std::optional<std::string> device_name;
        std::optional<std::string> os_version;
        std::optional<std::string> app_version;
        std::optional<std::string> fingerprint;
        std::chrono::system_clock::time_point created_at;
        std::optional<std::chrono::system_clock::time_point> last_seen_at;
    };
}
