#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <auth/domain/models/session.hpp>
#include <auth/services/ports/uow/db_transaction.hpp>

namespace smirkly::auth::services::ports {
    struct NewSessionData final {
        std::string user_id;
        std::optional<std::string> device_id;
        std::string refresh_token_hash;
        std::optional<std::string> ip;
        std::optional<std::string> user_agent;
        std::chrono::system_clock::time_point expires_at;
        std::string token_family_id;
        std::optional<std::string> replaced_by_session_id;
    };

    class SessionRepository {
    public:
        virtual ~SessionRepository() = default;

        virtual domain::models::Session Insert(
            DbTransaction &tx,
            const NewSessionData &data
        ) = 0;

        virtual std::optional<domain::models::Session> FindById(std::string_view session_id) = 0;

        virtual void Revoke(DbTransaction &tx, std::string_view session_id) = 0;

        virtual void UpdateLastUsed(
            DbTransaction &tx,
            std::string_view session_id,
            std::chrono::system_clock::time_point last_used_at
        ) = 0;
    };
}
