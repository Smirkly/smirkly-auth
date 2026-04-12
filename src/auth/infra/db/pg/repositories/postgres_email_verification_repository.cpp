#include <auth/infra/db/pg/repositories/postgres_email_verification_repository.hpp>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/io/row_types.hpp>

#include <auth/infra/db/pg/mappers/email_verification_mapper.hpp>
#include <auth/infra/db/pg/transactions/pg_transaction.hpp>
#include <auth/infra/db/pg/transactions/pg_tx_cast.hpp>
#include <smirkly::auth/sql_queries.hpp>

namespace smirkly::auth::infra::db::pg {
    PostgresEmailVerificationRepository::PostgresEmailVerificationRepository(
        USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster)
        : pg_cluster_(std::move(pg_cluster)) {
    }

    services::ports::EmailVerification PostgresEmailVerificationRepository::Insert(
        services::ports::DbTransaction &tx,
        const services::ports::NewEmailVerificationData &data) {
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

    std::optional<services::ports::EmailVerification> PostgresEmailVerificationRepository::FindActiveByUserId(
        std::string_view user_id,
        std::chrono::system_clock::time_point now) {
        const auto res = pg_cluster_->Execute(
            USERVER_NAMESPACE::storages::postgres::ClusterHostType::kSlave,
            sql::kEmailVerificationsFindActiveByUserId,
            user_id,
            USERVER_NAMESPACE::storages::postgres::TimePointTz{now}
        );

        if (res.IsEmpty()) {
            return std::nullopt;
        }

        const auto row = res.AsSingleRow<types::EmailVerificationPg>(USERVER_NAMESPACE::storages::postgres::kRowTag);
        return mappers::ToDomain(row);
    }

    void PostgresEmailVerificationRepository::MarkUsed(
        services::ports::DbTransaction &tx,
        std::string_view verification_id,
        std::chrono::system_clock::time_point used_at) {
        auto &pg_tx = AsPgTx(tx, "PostgresEmailVerificationRepository::MarkUsed");

        pg_tx.Native().Execute(
            sql::kEmailVerificationsMarkUsed,
            verification_id,
            USERVER_NAMESPACE::storages::postgres::TimePointTz{used_at}
        );
    }

    void PostgresEmailVerificationRepository::IncrementAttempts(
        services::ports::DbTransaction &tx,
        std::string_view verification_id,
        std::chrono::system_clock::time_point now) {
        auto &pg_tx = AsPgTx(tx, "PostgresEmailVerificationRepository::IncrementAttempts");

        pg_tx.Native().Execute(
            sql::kEmailVerificationsIncrementAttempts,
            verification_id,
            USERVER_NAMESPACE::storages::postgres::TimePointTz{now}
        );
    }
}
