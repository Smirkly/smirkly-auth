#include <auth/infra/db/pg/repositories/postgres_email_verification_repository.hpp>

#include <cstdint>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/io/row_types.hpp>

#include <auth/infra/db/pg/mappers/email_verification_mapper.hpp>
#include <auth/infra/db/pg/transactions/pg_transaction.hpp>
#include <auth/infra/db/pg/transactions/pg_tx_cast.hpp>
#include <smirkly::auth/sql_queries.hpp>

namespace smirkly::auth::infra::db::pg {
    namespace pgsql = USERVER_NAMESPACE::storages::postgres;
    namespace ports = services::ports;

    PostgresEmailVerificationRepository::PostgresEmailVerificationRepository(
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster)
        : pg_cluster_(std::move(pg_cluster)) {
    }

    ports::EmailVerification PostgresEmailVerificationRepository::Insert(
        ports::DbTransaction &tx,
        const ports::NewEmailVerificationData &data) {
        try {
            auto &pg_tx = AsPgTx(tx, "PostgresEmailVerificationRepository::Insert");

            const auto res = pg_tx.Native().Execute(
                sql::kEmailVerificationsInsert,
                data.user_id,
                data.code_hash,
                USERVER_NAMESPACE::storages::postgres::TimePointTz{data.expires_at},
                data.ip,
                data.user_agent
            );

            const auto row = res.AsSingleRow<types::EmailVerificationPg>(userver::storages::postgres::kRowTag);
            return mappers::ToDomain(row);
        } catch (const USERVER_NAMESPACE::storages::postgres::UniqueViolation &e) {
            const auto constraint = e.GetConstraint();
            throw;
        }
    }

    std::optional<ports::EmailVerification> PostgresEmailVerificationRepository::FindActiveByUserId(
        std::string_view user_id,
        std::chrono::system_clock::time_point now,
        std::size_t max_attempts) {
        const auto res = pg_cluster_->Execute(
            pgsql::ClusterHostType::kMaster,
            sql::kEmailVerificationsFindActiveByUserId,
            user_id,
            pgsql::TimePointTz{now},
            static_cast<std::int32_t>(max_attempts)
        );

        if (res.IsEmpty()) {
            return std::nullopt;
        }

        const auto row = res.AsSingleRow<types::EmailVerificationPg>(USERVER_NAMESPACE::storages::postgres::kRowTag);
        return mappers::ToDomain(row);
    }

    void PostgresEmailVerificationRepository::MarkUsed(
        ports::DbTransaction &tx,
        std::string_view verification_id,
        std::chrono::system_clock::time_point used_at) {
        auto &pg_tx = AsPgTx(tx, "PostgresEmailVerificationRepository::MarkUsed");

        pg_tx.Native().Execute(
            sql::kEmailVerificationsMarkUsed,
            verification_id,
            USERVER_NAMESPACE::storages::postgres::TimePointTz{used_at}
        );
    }

    void PostgresEmailVerificationRepository::MarkActiveUsedByUserId(
        ports::DbTransaction &tx,
        std::string_view user_id,
        std::chrono::system_clock::time_point used_at) {
        auto &pg_tx = AsPgTx(tx, "PostgresEmailVerificationRepository::MarkActiveUsedByUserId");

        pg_tx.Native().Execute(
            sql::kEmailVerificationsMarkActiveUsedByUserId,
            user_id,
            USERVER_NAMESPACE::storages::postgres::TimePointTz{used_at}
        );
    }

    void PostgresEmailVerificationRepository::IncrementAttempts(
        ports::DbTransaction &tx,
        std::string_view verification_id,
        std::chrono::system_clock::time_point now,
        std::size_t max_attempts) {
        auto &pg_tx = AsPgTx(tx, "PostgresEmailVerificationRepository::IncrementAttempts");

        pg_tx.Native().Execute(
            sql::kEmailVerificationsIncrementAttempts,
            verification_id,
            pgsql::TimePointTz{now},
            static_cast<std::int32_t>(max_attempts)
        );
    }

    ports::EmailVerificationAttemptCounters PostgresEmailVerificationRepository::CountRecentAttempts(
        std::string_view email,
        const std::optional<std::string> &user_id,
        const std::optional<std::string> &ip,
        std::chrono::system_clock::time_point since) {
        const auto res = pg_cluster_->Execute(
            pgsql::ClusterHostType::kMaster,
            sql::kEmailVerificationAttemptsCountRecent,
            email,
            user_id.value_or(""),
            ip.value_or(""),
            pgsql::TimePointTz{since}
        );

        const auto row = res.Front();

        return {
            .email = static_cast<std::size_t>(row["email_attempts"].As<std::int64_t>()),
            .user = static_cast<std::size_t>(row["user_attempts"].As<std::int64_t>()),
            .ip = static_cast<std::size_t>(row["ip_attempts"].As<std::int64_t>())
        };
    }

    void PostgresEmailVerificationRepository::RecordAttempt(
        ports::DbTransaction &tx,
        std::string_view email,
        const std::optional<std::string> &user_id,
        const std::optional<std::string> &ip,
        const std::optional<std::string> &user_agent,
        std::chrono::system_clock::time_point now) {
        auto &pg_tx = AsPgTx(tx, "PostgresEmailVerificationRepository::RecordAttempt");

        pg_tx.Native().Execute(
            sql::kEmailVerificationAttemptsInsert,
            email,
            user_id.value_or(""),
            ip.value_or(""),
            user_agent,
            pgsql::TimePointTz{now}
        );
    }
}
