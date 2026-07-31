#pragma once

#include <memory>

#include <auth/services/ports/repositories/email_verification_repository.hpp>

USERVER_NAMESPACE_BEGIN
namespace storages::postgres {
class Cluster;
using ClusterPtr = std::shared_ptr<Cluster>;
}  // namespace storages::postgres

USERVER_NAMESPACE_END

namespace smirkly::auth::infra::db::pg {
namespace ports = services::ports;

class PostgresEmailVerificationRepository
    : public ports::EmailVerificationRepository {
 public:
  explicit PostgresEmailVerificationRepository(
      USERVER_NAMESPACE::storages::postgres::ClusterPtr pg_cluster);

  ports::EmailVerification Insert(
      ports::DbTransaction& tx,
      const ports::NewEmailVerificationData& data) override;

  std::optional<ports::EmailVerification> FindActiveByUserId(
      std::string_view user_id, std::chrono::system_clock::time_point now,
      std::size_t max_attempts) override;

  [[nodiscard]] bool MarkUsed(ports::DbTransaction& tx,
                              std::string_view verification_id,
                              std::chrono::system_clock::time_point used_at,
                              std::size_t max_attempts) override;

  void MarkActiveUsedByUserId(
      ports::DbTransaction& tx, std::string_view user_id,
      std::chrono::system_clock::time_point used_at) override;

  void IncrementAttempts(ports::DbTransaction& tx,
                         std::string_view verification_id,
                         std::chrono::system_clock::time_point now,
                         std::size_t max_attempts) override;

  [[nodiscard]] bool TryRecordAttempt(
      ports::DbTransaction& tx, std::string_view email,
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
