#pragma once

#include <optional>
#include <string>

#include <userver/storages/postgres/io/chrono.hpp>
#include <userver/storages/postgres/io/user_types.hpp>

namespace smirkly::auth::infra::db::pg::types {
    struct DevicePg final {
        std::string id;
        std::string user_id;
        std::string device_type;
        std::optional<std::string> device_name;
        std::optional<std::string> os_version;
        std::optional<std::string> app_version;
        std::optional<std::string> fingerprint;
        USERVER_NAMESPACE::storages::postgres::TimePointTz created_at;
        std::optional<USERVER_NAMESPACE::storages::postgres::TimePointTz> last_seen_at;
    };
}
