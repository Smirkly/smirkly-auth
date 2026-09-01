#include <auth/infra/db/pg/repositories/postgres_sign_up_attempt_repository.hpp>

#include <cstdint>

#include <userver/storages/postgres/io/chrono.hpp>

#include <auth/infra/db/pg/transactions/pg_tx_cast.hpp>
#include <smirkly::auth/sql_queries.hpp>

namespace smirkly::auth::infra::db::pg {
namespace pgsql = USERVER_NAMESPACE::storages::postgres;

bool PostgresSignUpAttemptRepository::TryRecordAttempt(
    ports::DbTransaction& tx, std::string_view ip,
    std::chrono::system_clock::time_point now,
    std::chrono::system_clock::time_point since,
    std::size_t max_attempts_per_ip) {
  auto& pg_tx = AsPgTx(tx, "PostgresSignUpAttemptRepository::TryRecordAttempt");

  pg_tx.Native().Execute(sql::kSignUpAttemptsLockScope, ip);
  const auto result =
      pg_tx.Native().Execute(sql::kSignUpAttemptsTryRecord, ip,
                             pgsql::TimePointTz{now}, pgsql::TimePointTz{since},
                             static_cast<std::int64_t>(max_attempts_per_ip));

  return !result.IsEmpty();
}

}  // namespace smirkly::auth::infra::db::pg
