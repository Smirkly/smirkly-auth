#pragma once

#include <memory>

#include <auth/services/ports/repositories/sign_in_attempt_repository.hpp>

USERVER_NAMESPACE_BEGIN
namespace storages::postgres {
class Cluster;
using ClusterPtr = std::shared_ptr<Cluster>;
}  // namespace storages::postgres
USERVER_NAMESPACE_END

namespace smirkly::auth::infra::db::pg {
namespace ports = services::ports;

class PostgresSignInAttemptRepository final
    : public ports::SignInAttemptRepository {
 public:
  explicit PostgresSignInAttemptRepository(
      USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster);

  ports::SignInAttemptCounters CountRecentAttempts(
      std::string_view login_identifier,
      const std::optional<std::string>& user_id,
      const std::optional<std::string>& ip,
      std::chrono::system_clock::time_point since) override;

  [[nodiscard]] bool TryRecordAttempt(
      ports::DbTransaction& tx, std::string_view login_identifier,
      const std::optional<std::string>& user_id,
      const std::optional<std::string>& ip,
      const std::optional<std::string>& user_agent,
      std::chrono::system_clock::time_point now,
      std::chrono::system_clock::time_point since,
      std::size_t max_attempts_per_identifier,
      std::size_t max_attempts_per_user,
      std::size_t max_attempts_per_ip) override;

 private:
  USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster_;
};
}  // namespace smirkly::auth::infra::db::pg
