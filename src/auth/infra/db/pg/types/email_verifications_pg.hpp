#pragma once

#include <chrono>
#include <optional>
#include <string>

#include <userver/storages/postgres/io/chrono.hpp>

namespace smirkly::auth::infra::db::pg::types {
    namespace pg = USERVER_NAMESPACE::storages::postgres;

    struct EmailVerificationPg {
        std::string id;
        std::string user_id;
        std::string code_hash;
        USERVER_NAMESPACE::storages::postgres::TimePointTz created_at;
        USERVER_NAMESPACE::storages::postgres::TimePointTz expires_at;
        std::optional<USERVER_NAMESPACE::storages::postgres::TimePointTz> used_at;
        std::int32_t attempts{0};
        std::optional<USERVER_NAMESPACE::storages::postgres::TimePointTz> last_attempt_at;
        std::optional<std::string> ip;
        std::optional<std::string> user_agent;
    };
}
