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
    class PostgresSessionRepository final : public services::ports::SessionRepository {
    public:
        explicit PostgresSessionRepository(USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster);

        domain::models::Session Insert(
            services::ports::DbTransaction &tx,
            const services::ports::NewSessionData &data) override;

        std::optional<domain::models::Session> FindById(std::string_view session_id) override;

        std::vector<domain::models::Session> ListActiveByUserId(std::string_view user_id) override;

        void Revoke(
            services::ports::DbTransaction &tx,
            std::string_view session_id
        ) override;

        bool RevokeByUserId(
            services::ports::DbTransaction &tx,
            std::string_view session_id,
            std::string_view user_id
        ) override;

        bool RevokeAndReplace(
            services::ports::DbTransaction &tx,
            std::string_view session_id,
            std::string_view replacement_session_id
        ) override;

        void RevokeByTokenFamily(
            services::ports::DbTransaction &tx,
            std::string_view user_id,
            std::string_view token_family_id
        ) override;

        void UpdateLastUsed(
            services::ports::DbTransaction &tx,
            std::string_view session_id,
            std::chrono::system_clock::time_point last_used_at
        ) override;

    private:
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster_;
    };
}
