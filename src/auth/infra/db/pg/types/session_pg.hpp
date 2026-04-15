#pragma once

#include <optional>
#include <string>

#include <userver/storages/postgres/io/chrono.hpp>
#include <userver/storages/postgres/io/user_types.hpp>

namespace smirkly::auth::infra::db::pg::types {
    struct SessionPg final {
        std::string id;
        std::string user_id;
        std::optional<std::string> device_id;
        std::string refresh_token_hash;
        std::optional<std::string> ip;
        std::optional<std::string> user_agent;
        USERVER_NAMESPACE::storages::postgres::TimePointTz created_at;
        std::optional<USERVER_NAMESPACE::storages::postgres::TimePointTz> last_used_at;
        USERVER_NAMESPACE::storages::postgres::TimePointTz expires_at;
        std::optional<USERVER_NAMESPACE::storages::postgres::TimePointTz> revoked_at;
        std::string token_family_id;
        std::optional<std::string> replaced_by_session_id;
    };
}
