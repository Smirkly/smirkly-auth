#include <auth/infra/db/pg/repositories/postgres_password_reset_repository.hpp>

#include <cstdint>
#include <utility>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/io/row_types.hpp>

#include <auth/infra/db/pg/mappers/password_reset_mapper.hpp>
#include <auth/infra/db/pg/transactions/pg_tx_cast.hpp>
#include <smirkly::auth/sql_queries.hpp>

namespace smirkly::auth::infra::db::pg {
namespace pgsql = USERVER_NAMESPACE::storages::postgres;

PostgresPasswordResetRepository::PostgresPasswordResetRepository(
    USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster)
    : pg_cluster_(std::move(pg_cluster)) {}

services::ports::PasswordReset PostgresPasswordResetRepository::Insert(
    services::ports::DbTransaction& tx,
    const services::ports::NewPasswordResetData& data) {
  auto& pg_tx = AsPgTx(tx, "PostgresPasswordResetRepository::Insert");

  const auto res = pg_tx.Native().Execute(
      sql::kPasswordResetsInsert, data.user_id, data.token_hash,
      pgsql::TimePointTz{data.expires_at}, data.ip, data.user_agent);

  const auto row = res.AsSingleRow<types::PasswordResetPg>(pgsql::kRowTag);
  return mappers::ToDomain(row);
}

std::optional<services::ports::PasswordReset>
PostgresPasswordResetRepository::FindActiveByUserId(
    std::string_view user_id, std::chrono::system_clock::time_point now,
    std::size_t max_attempts) {
  const auto res = pg_cluster_->Execute(
      pgsql::ClusterHostType::kMaster, sql::kPasswordResetsFindActiveByUserId,
      user_id, pgsql::TimePointTz{now},
      static_cast<std::int32_t>(max_attempts));

  if (res.IsEmpty()) {
    return std::nullopt;
  }

  const auto row = res.AsSingleRow<types::PasswordResetPg>(pgsql::kRowTag);
  return mappers::ToDomain(row);
}

bool PostgresPasswordResetRepository::MarkUsed(
    services::ports::DbTransaction& tx, std::string_view reset_id,
    std::chrono::system_clock::time_point used_at, std::size_t max_attempts) {
  auto& pg_tx = AsPgTx(tx, "PostgresPasswordResetRepository::MarkUsed");

  const auto res = pg_tx.Native().Execute(
      sql::kPasswordResetsMarkUsed, reset_id, pgsql::TimePointTz{used_at},
      static_cast<std::int32_t>(max_attempts));

  return !res.IsEmpty();
}

void PostgresPasswordResetRepository::MarkActiveUsedByUserId(
    services::ports::DbTransaction& tx, std::string_view user_id,
    std::chrono::system_clock::time_point used_at) {
  auto& pg_tx =
      AsPgTx(tx, "PostgresPasswordResetRepository::MarkActiveUsedByUserId");

  pg_tx.Native().Execute(sql::kPasswordResetsMarkActiveUsedByUserId, user_id,
                         pgsql::TimePointTz{used_at});
}

void PostgresPasswordResetRepository::IncrementAttempts(
    services::ports::DbTransaction& tx, std::string_view reset_id,
    std::chrono::system_clock::time_point now, std::size_t max_attempts) {
  auto& pg_tx =
      AsPgTx(tx, "PostgresPasswordResetRepository::IncrementAttempts");

  pg_tx.Native().Execute(sql::kPasswordResetsIncrementAttempts, reset_id,
                         pgsql::TimePointTz{now},
                         static_cast<std::int32_t>(max_attempts));
}

bool PostgresPasswordResetRepository::TryRecordAttempt(
    services::ports::DbTransaction& tx, std::string_view email,
    const std::optional<std::string>& user_id,
    const std::optional<std::string>& ip,
    const std::optional<std::string>& user_agent,
    std::chrono::system_clock::time_point now,
    std::chrono::system_clock::time_point since,
    std::size_t max_attempts_per_email, std::size_t max_attempts_per_user,
    std::size_t max_attempts_per_ip) {
  auto& pg_tx = AsPgTx(tx, "PostgresPasswordResetRepository::TryRecordAttempt");

  pg_tx.Native().Execute(sql::kPasswordResetAttemptsLockScopes, email,
                         user_id.value_or(""), ip.value_or(""));

  const auto res =
      pg_tx.Native().Execute(sql::kPasswordResetAttemptsTryRecord, email,
                             user_id.value_or(""), ip.value_or(""), user_agent,
                             pgsql::TimePointTz{now}, pgsql::TimePointTz{since},
                             static_cast<std::int64_t>(max_attempts_per_email),
                             static_cast<std::int64_t>(max_attempts_per_user),
                             static_cast<std::int64_t>(max_attempts_per_ip));

  return !res.IsEmpty();
}

}  // namespace smirkly::auth::infra::db::pg
