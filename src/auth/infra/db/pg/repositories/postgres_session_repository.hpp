#pragma once

#include <memory>
#include <string_view>

#include <auth/services/ports/repositories/session_repository.hpp>

USERVER_NAMESPACE_BEGIN
    namespace storages::postgres {
        class Cluster;
        using ClusterPtr = std::shared_ptr<Cluster>;
    }

USERVER_NAMESPACE_END

namespace smirkly::auth::infra::db::pg {
    namespace ports = services::ports;

    class PostgresSessionRepository final : public ports::SessionRepository {
    public:
        explicit PostgresSessionRepository(USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster);

        domain::models::Session Insert(
            ports::DbTransaction &tx,
            const ports::NewSessionData &data) override;

        std::optional<domain::models::Session> FindById(
            std::string_view session_id,
            ports::ReadConsistency consistency
        ) override;

        std::vector<domain::models::Session> ListActiveByUserId(
            std::string_view user_id,
            ports::ReadConsistency consistency
        ) override;

        void Revoke(
            ports::DbTransaction &tx,
            std::string_view session_id
        ) override;

        bool RevokeByUserId(
            ports::DbTransaction &tx,
            std::string_view session_id,
            std::string_view user_id
        ) override;

        void RevokeAllByUserId(
            ports::DbTransaction &tx,
            std::string_view user_id
        ) override;

        bool RevokeAndReplace(
            ports::DbTransaction &tx,
            std::string_view session_id,
            std::string_view replacement_session_id
        ) override;

        void RevokeByTokenFamily(
            ports::DbTransaction &tx,
            std::string_view user_id,
            std::string_view token_family_id
        ) override;

        void UpdateLastUsed(
            ports::DbTransaction &tx,
            std::string_view session_id,
            std::chrono::system_clock::time_point last_used_at
        ) override;

    private:
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster_;
    };
}
