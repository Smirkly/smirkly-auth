#include <utility>

#include <userver/formats/json/serialize.hpp>
#include <userver/formats/json/value_builder.hpp>
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
    : pg_cluster_(std::move(pg_cluster)) {}

void PostgresEmailOutboxRepository::Insert(
    services::ports::DbTransaction& tx,
    const services::ports::EnqueueEmail& job) {
  auto& pg_tx = AsPgTx(tx, "PostgresEmailOutboxRepository::Insert");

  USERVER_NAMESPACE::formats::json::ValueBuilder payload;
  for (const auto& [key, value] : job.payload) {
    payload[key] = value;
  }

  pg_tx.Native().Execute(
      sql::kEmailOutboxInsert, job.to_email, job.template_name,
      USERVER_NAMESPACE::formats::json::ToString(payload.ExtractValue()),
      job.correlation_id);
}

void PostgresEmailOutboxRepository::Insert(
    const services::ports::EnqueueEmail& job) {
  auto tx = PgTransaction::Begin(
      pg_cluster_, "PostgresEmailOutboxRepository::Insert.AutoTx");

  PostgresEmailOutboxRepository::Insert(tx, job);

  tx.Commit();
}

std::vector<services::ports::EmailOutboxEntry>
PostgresEmailOutboxRepository::ClaimBatch(
    services::ports::DbTransaction& tx, std::size_t batch_size,
    std::chrono::system_clock::time_point now,
    std::chrono::seconds stuck_timeout, std::size_t max_attempts) {
  auto& pg_tx = AsPgTx(tx, "PostgresEmailOutboxRepository::ClaimBatch");

  const auto lock_until = now + stuck_timeout;

  const auto limit = static_cast<std::int32_t>(batch_size);
  const auto max_attempts_i32 = static_cast<std::int32_t>(max_attempts);

  const USERVER_NAMESPACE::storages::postgres::TimePointTz now_tz{now};
  const USERVER_NAMESPACE::storages::postgres::TimePointTz lock_until_tz{
      lock_until};

  auto res = pg_tx.Native().Execute(sql::kEmailOutboxClaimBatch, limit, now_tz,
                                    lock_until_tz, max_attempts_i32);

  std::vector<services::ports::EmailOutboxEntry> result;
  result.reserve(res.Size());

  for (const auto& row : res) {
    services::ports::EmailOutboxEntry entry;

    entry.id = row["id"].As<std::string>();
    entry.lease_id = row["lease_id"].As<std::string>();
    entry.to_email = row["to_email"].As<std::string>();
    entry.correlation_id = row["correlation_id"].As<std::string>();
    entry.template_name = row["template"].As<std::string>();
    entry.attempts = row["attempts"].As<std::int32_t>();

    const auto payload =
        row["payload"].As<USERVER_NAMESPACE::formats::json::Value>();
    entry.payload_json = USERVER_NAMESPACE::formats::json::ToString(payload);

    const auto next_attempt_at_tz =
        row["next_attempt_at"]
            .As<USERVER_NAMESPACE::storages::postgres::TimePointTz>();
    entry.next_attempt_at = next_attempt_at_tz.GetUnderlying();

    result.emplace_back(std::move(entry));
  }

  return result;
}

bool PostgresEmailOutboxRepository::MarkSent(
    services::ports::DbTransaction& tx, std::string_view id,
    std::string_view lease_id, std::chrono::system_clock::time_point now,
    std::string_view last_error) {
  auto& pg_tx = AsPgTx(tx, "PostgresEmailOutboxRepository::MarkSent");

  const USERVER_NAMESPACE::storages::postgres::TimePointTz now_tz{now};

  const auto res = pg_tx.Native().Execute(sql::kEmailOutboxMarkSent, id,
                                          lease_id, last_error, now_tz);

  return !res.IsEmpty();
}

bool PostgresEmailOutboxRepository::Reschedule(
    services::ports::DbTransaction& tx, std::string_view id,
    std::string_view lease_id, std::chrono::system_clock::time_point next_at,
    std::string_view last_error) {
  auto& pg_tx = AsPgTx(tx, "PostgresEmailOutboxRepository::Reschedule");

  const USERVER_NAMESPACE::storages::postgres::TimePointTz next_at_tz{next_at};
  const USERVER_NAMESPACE::storages::postgres::TimePointTz update_at_tz{
      std::chrono::system_clock::now()};

  const auto res =
      pg_tx.Native().Execute(sql::kEmailOutboxReschedule, id, lease_id,
                             next_at_tz, last_error, update_at_tz);

  return !res.IsEmpty();
}

bool PostgresEmailOutboxRepository::MarkDead(
    services::ports::DbTransaction& tx, std::string_view id,
    std::string_view lease_id, std::chrono::system_clock::time_point now,
    std::string_view last_error) {
  auto& pg_tx = AsPgTx(tx, "PostgresEmailOutboxRepository::MarkDead");

  const USERVER_NAMESPACE::storages::postgres::TimePointTz now_tz{now};

  const auto res = pg_tx.Native().Execute(sql::kEmailOutboxMarkDead, id,
                                          lease_id, last_error, now_tz);

  return !res.IsEmpty();
}
}  // namespace smirkly::auth::infra::db::pg
