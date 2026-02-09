#include <utility>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/cluster_types.hpp>
#include <userver/storages/postgres/io/chrono.hpp>

#include <auth/infra/db/pg/repositories/postgres_email_outbox_repository.hpp>
#include <auth/infra/db/pg/transactions/pg_transaction.hpp>
#include <auth/infra/db/pg/transactions/pg_tx_cast.hpp>
#include <smirkly::auth/sql_queries.hpp>

namespace smirkly::auth::infra::db::pg {
    PostgresEmailOutboxRepository::PostgresEmailOutboxRepository(
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster)
        : pg_cluster_(std::move(pg_cluster)) {
    }

    void PostgresEmailOutboxRepository::Insert(services::ports::DbTransaction &tx,
                                               const services::ports::EnqueueVerificationEmail &job) {
        auto &pg_tx = AsPgTx(tx, "PostgresEmailOutboxRepository::Insert");

        pg_tx.Native().Execute(
            sql::kEmailOutboxInsert,
            job.to_email,
            job.code,
            job.locale,
            job.correlation_id
        );
    }

    void PostgresEmailOutboxRepository::Insert(const services::ports::EnqueueVerificationEmail &job) {
        auto tx = PgTransaction::Begin(
            pg_cluster_,
            "PostgresEmailOutboxRepository::Insert.AutoTx"
        );

        PostgresEmailOutboxRepository::Insert(tx, job);

        tx.Commit();
    }

    std::vector<services::ports::EmailOutboxEntry> PostgresEmailOutboxRepository::ClaimBatch(
        services::ports::DbTransaction &tx,
        std::size_t batch_size,
        std::chrono::system_clock::time_point now,
        std::chrono::seconds stuck_timeout,
        std::size_t max_attempts
    ) {
        auto &pg_tx = AsPgTx(tx, "PostgresEmailOutboxRepository::ClaimBatch");

        const auto lock_until = now + stuck_timeout;

        const auto limit = static_cast<std::int32_t>(batch_size);
        const auto max_attempts_i32 = static_cast<std::int32_t>(max_attempts);

        const USERVER_NAMESPACE::storages::postgres::TimePointTz now_tz{now};
        const USERVER_NAMESPACE::storages::postgres::TimePointTz lock_until_tz{lock_until};

        auto res = pg_tx.Native().Execute(
            sql::kEmailOutboxClaimBatch,
            limit,
            now_tz,
            lock_until_tz,
            max_attempts_i32
        );

        std::vector<services::ports::EmailOutboxEntry> result;
        result.reserve(res.Size());

        for (const auto &row: res) {
            services::ports::EmailOutboxEntry entry;

            entry.id = row["id"].As<std::string>();
            entry.to_email = row["to_email"].As<std::string>();
            entry.correlation_id = row["correlation_id"].As<std::string>();
            entry.template_name = row["template"].As<std::string>();
            entry.attempts = row["attempts"].As<std::int32_t>();

            const auto payload = row["payload"].As<USERVER_NAMESPACE::formats::json::Value>();
            entry.payload_json = USERVER_NAMESPACE::formats::json::ToString(payload);

            const auto next_attempt_at_tz = row["next_attempt_at"].As<
                USERVER_NAMESPACE::storages::postgres::TimePointTz>();
            entry.next_attempt_at = next_attempt_at_tz.GetUnderlying();

            result.emplace_back(std::move(entry));
        }

        return result;
    }

    void PostgresEmailOutboxRepository::MarkSent(
        services::ports::DbTransaction &tx,
        std::string_view id,
        std::chrono::system_clock::time_point now,
        std::string_view last_error
    ) {
        auto &pg_tx = AsPgTx(tx, "PostgresEmailOutboxRepository::MarkSent");

        const USERVER_NAMESPACE::storages::postgres::TimePointTz now_tz{now};

        pg_tx.Native().Execute(
            sql::kEmailOutboxMarkSent,
            id,
            last_error,
            now_tz
        );
    }

    void PostgresEmailOutboxRepository::Reschedule(
        services::ports::DbTransaction &tx,
        std::string_view id,
        std::size_t next_attempt,
        std::chrono::system_clock::time_point next_at,
        std::string_view last_error
    ) {
        auto &pg_tx = AsPgTx(tx, "PostgresEmailOutboxRepository::Reschedule");

        const USERVER_NAMESPACE::storages::postgres::TimePointTz next_at_tz{next_at};
        const USERVER_NAMESPACE::storages::postgres::TimePointTz update_at_tz{std::chrono::system_clock::now()};

        const std::optional<USERVER_NAMESPACE::storages::postgres::TimePointTz> locked_until_null = std::nullopt;

        pg_tx.Native().Execute(
            sql::kEmailOutboxReschedule,
            id,
            next_at_tz,
            locked_until_null,
            last_error,
            update_at_tz
        );
    }

    void PostgresEmailOutboxRepository::MarkDead(
        services::ports::DbTransaction &tx,
        std::string_view id,
        std::chrono::system_clock::time_point now,
        std::string_view last_error
    ) {
        auto &pg_tx = AsPgTx(tx, "PostgresEmailOutboxRepository::Reschedule");

        const USERVER_NAMESPACE::storages::postgres::TimePointTz now_tz{now};

        pg_tx.Native().Execute(
            sql::kEmailOutboxMarkDead,
            id,
            last_error,
            now_tz
        );
    }
}
