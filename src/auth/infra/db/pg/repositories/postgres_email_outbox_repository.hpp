#pragma once

#include <memory>

#include <auth/services/ports/repositories/email_outbox_repository.hpp>

USERVER_NAMESPACE_BEGIN
    namespace storages::postgres {
        class Cluster;
        using ClusterPtr = std::shared_ptr<Cluster>;
    }

USERVER_NAMESPACE_END

namespace smirkly::auth::infra::db::pg {
    class PostgresEmailOutboxRepository : public services::ports::EmailOutboxRepository {
    public:
        explicit PostgresEmailOutboxRepository(USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster);

        void Insert(services::ports::DbTransaction &tx, const services::ports::EnqueueVerificationEmail &job) override;

        void Insert(const services::ports::EnqueueVerificationEmail &job) override;

        std::vector<services::ports::EmailOutboxEntry> ClaimBatch(
            services::ports::DbTransaction &tx,
            std::size_t batch_size,
            std::chrono::system_clock::time_point now,
            std::chrono::seconds stuck_timeout,
            std::size_t max_attempts
        ) override;

        void MarkSent(
            services::ports::DbTransaction &tx,
            std::string_view id,
            std::chrono::system_clock::time_point now,
            std::string_view last_error = {}
        ) override;

        void Reschedule(
            services::ports::DbTransaction &tx,
            std::string_view id,
            std::chrono::system_clock::time_point next_at,
            std::string_view last_error
        ) override;

        void MarkDead(
            services::ports::DbTransaction &tx,
            std::string_view id,
            std::chrono::system_clock::time_point now,
            std::string_view last_error
        ) override;

    private:
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster_;
    };
}
