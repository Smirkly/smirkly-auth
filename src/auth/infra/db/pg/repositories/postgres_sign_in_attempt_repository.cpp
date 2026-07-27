#include <auth/infra/db/pg/repositories/postgres_sign_in_attempt_repository.hpp>

#include <cstdint>
#include <utility>

#include <userver/storages/postgres/cluster.hpp>

#include <auth/infra/db/pg/transactions/pg_tx_cast.hpp>
#include <smirkly::auth/sql_queries.hpp>

namespace smirkly::auth::infra::db::pg {
namespace pgsql = USERVER_NAMESPACE::storages::postgres;
namespace ports = services::ports;

PostgresSignInAttemptRepository::PostgresSignInAttemptRepository(
    USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster)
    : pg_cluster_(std::move(pg_cluster)) {}

ports::SignInAttemptCounters
PostgresSignInAttemptRepository::CountRecentAttempts(
    std::string_view login_identifier,
    const std::optional<std::string>& user_id,
    const std::optional<std::string>& ip,
    std::chrono::system_clock::time_point since) {
  const auto res = pg_cluster_->Execute(
      pgsql::ClusterHostType::kMaster, sql::kSignInAttemptsCountRecent,
      login_identifier, user_id.value_or(""), ip.value_or(""),
      pgsql::TimePointTz{since});

  const auto row = res.Front();
  return {
      .identifier = static_cast<std::size_t>(
          row["identifier_attempts"].As<std::int64_t>()),
      .user = static_cast<std::size_t>(row["user_attempts"].As<std::int64_t>()),
      .ip = static_cast<std::size_t>(row["ip_attempts"].As<std::int64_t>())};
}

bool PostgresSignInAttemptRepository::TryRecordAttempt(
    ports::DbTransaction& tx, std::string_view login_identifier,
    const std::optional<std::string>& user_id,
    const std::optional<std::string>& ip,
    const std::optional<std::string>& user_agent,
    std::chrono::system_clock::time_point now,
    std::chrono::system_clock::time_point since,
    std::size_t max_attempts_per_identifier, std::size_t max_attempts_per_user,
    std::size_t max_attempts_per_ip) {
  auto& pg_tx = AsPgTx(tx, "PostgresSignInAttemptRepository::TryRecordAttempt");

  pg_tx.Native().Execute(sql::kSignInAttemptsLockScopes, login_identifier,
                         user_id.value_or(""), ip.value_or(""));

  const auto res = pg_tx.Native().Execute(
      sql::kSignInAttemptsTryRecord, login_identifier, user_id.value_or(""),
      ip.value_or(""), user_agent, pgsql::TimePointTz{now},
      pgsql::TimePointTz{since},
      static_cast<std::int64_t>(max_attempts_per_identifier),
      static_cast<std::int64_t>(max_attempts_per_user),
      static_cast<std::int64_t>(max_attempts_per_ip));

  return !res.IsEmpty();
}
}  // namespace smirkly::auth::infra::db::pg
