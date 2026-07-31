#pragma once

#include <memory>

#include <auth/services/ports/repositories/password_reset_repository.hpp>

USERVER_NAMESPACE_BEGIN
namespace storages::postgres {
class Cluster;
using ClusterPtr = std::shared_ptr<Cluster>;
}  // namespace storages::postgres
USERVER_NAMESPACE_END

namespace smirkly::auth::infra::db::pg {

class PostgresPasswordResetRepository final
    : public services::ports::PasswordResetRepository {
 public:
  explicit PostgresPasswordResetRepository(
      USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster);

  services::ports::PasswordReset Insert(
      services::ports::DbTransaction& tx,
      const services::ports::NewPasswordResetData& data) override;

  std::optional<services::ports::PasswordReset> FindActiveByUserId(
      std::string_view user_id, std::chrono::system_clock::time_point now,
      std::size_t max_attempts) override;

  bool MarkUsed(services::ports::DbTransaction& tx, std::string_view reset_id,
                std::chrono::system_clock::time_point used_at,
                std::size_t max_attempts) override;

  void MarkActiveUsedByUserId(
      services::ports::DbTransaction& tx, std::string_view user_id,
      std::chrono::system_clock::time_point used_at) override;

  void IncrementAttempts(services::ports::DbTransaction& tx,
                         std::string_view reset_id,
                         std::chrono::system_clock::time_point now,
                         std::size_t max_attempts) override;

  [[nodiscard]] bool TryRecordAttempt(
      services::ports::DbTransaction& tx, std::string_view email,
      const std::optional<std::string>& user_id,
      const std::optional<std::string>& ip,
      const std::optional<std::string>& user_agent,
      std::chrono::system_clock::time_point now,
      std::chrono::system_clock::time_point since,
      std::size_t max_attempts_per_email, std::size_t max_attempts_per_user,
      std::size_t max_attempts_per_ip) override;

 private:
  USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster_;
};

}  // namespace smirkly::auth::infra::db::pg
