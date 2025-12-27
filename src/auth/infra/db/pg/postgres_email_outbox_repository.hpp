#pragma once

#include <memory>

#include <auth/services/ports/email_outbox_repository.hpp>

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


        void Insert(const services::ports::EnqueueVerificationEmail &job) override;

    private:
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster_;
    };
}
