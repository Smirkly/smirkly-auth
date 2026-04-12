#pragma once

#include <memory>

#include <auth/services/ports/repositories/email_verification_repository.hpp>

USERVER_NAMESPACE_BEGIN
    namespace storages::postgres {
        class Cluster;
        using ClusterPtr = std::shared_ptr<Cluster>;
    }

USERVER_NAMESPACE_END

namespace smirkly::auth::infra::db::pg {
    class PostgresEmailVerificationRepository : public services::ports::EmailVerificationRepository {
    public:
        explicit PostgresEmailVerificationRepository(USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster);

        services::ports::EmailVerification Insert(
            services::ports::DbTransaction &tx,
            const services::ports::NewEmailVerificationData &data) override;

        std::optional<services::ports::EmailVerification> FindActiveByUserId(
            std::string_view user_id,
            std::chrono::system_clock::time_point now) override;

        void MarkUsed(
            services::ports::DbTransaction &tx,
            std::string_view verification_id,
            std::chrono::system_clock::time_point) override;

        void IncrementAttempts(
            services::ports::DbTransaction &tx,
            std::string_view verification_id,
            std::chrono::system_clock::time_point now) override;

    private:
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster_;
    };
}
