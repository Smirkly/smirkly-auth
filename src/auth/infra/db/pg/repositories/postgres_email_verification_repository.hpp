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
    namespace ports = services::ports;

    class PostgresEmailVerificationRepository : public ports::EmailVerificationRepository {
    public:
        explicit PostgresEmailVerificationRepository(USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster);

        ports::EmailVerification Insert(
            ports::DbTransaction &tx,
            const ports::NewEmailVerificationData &data) override;

        std::optional<ports::EmailVerification> FindActiveByUserId(
            std::string_view user_id,
            std::chrono::system_clock::time_point now,
            std::size_t max_attempts) override;

        void MarkUsed(
            ports::DbTransaction &tx,
            std::string_view verification_id,
            std::chrono::system_clock::time_point) override;

        void IncrementAttempts(
            ports::DbTransaction &tx,
            std::string_view verification_id,
            std::chrono::system_clock::time_point now,
            std::size_t max_attempts) override;

        ports::EmailVerificationAttemptCounters CountRecentAttempts(
            std::string_view email,
            const std::optional<std::string> &user_id,
            const std::optional<std::string> &ip,
            std::chrono::system_clock::time_point since) override;

        void RecordAttempt(
            ports::DbTransaction &tx,
            std::string_view email,
            const std::optional<std::string> &user_id,
            const std::optional<std::string> &ip,
            const std::optional<std::string> &user_agent,
            std::chrono::system_clock::time_point now) override;

    private:
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster_;
    };
}
