#pragma once

#include <chrono>
#include <optional>
#include <string>

#include <userver/storages/postgres/io/chrono.hpp>

namespace smirkly::auth::infra::db::pg::types {
    namespace pg = USERVER_NAMESPACE::storages::postgres;

    struct UserPg {
        std::string id;
        std::string username;
        std::optional<std::string> email;
        std::optional<std::string> phone;
        std::string password_hash;
        bool is_email_verified;
        bool is_phone_verified;
        pg::TimePointTz created_at;
        pg::TimePointTz password_updated_at;
        std::optional<pg::TimePointTz> deleted_at;
    };
}
