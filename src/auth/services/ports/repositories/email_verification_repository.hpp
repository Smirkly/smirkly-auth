#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <auth/services/ports/uow/db_transaction.hpp>

namespace smirkly::auth::services::ports {
struct NewEmailVerificationData {
  std::string user_id;
  std::string code_hash;
  std::chrono::system_clock::time_point expires_at;
  std::optional<std::string> ip;
  std::optional<std::string> user_agent;
};

struct EmailVerification {
  std::string id;
  std::string user_id;
  std::string code_hash;
  std::chrono::system_clock::time_point expires_at;
  std::optional<std::chrono::system_clock::time_point> used_at;
  std::int32_t attempts{0};
};

struct EmailVerificationAttemptCounters {
  std::size_t email{0};
  std::size_t user{0};
  std::size_t ip{0};
};

class EmailVerificationRepository {
 public:
  virtual ~EmailVerificationRepository() = default;

  virtual EmailVerification Insert(DbTransaction& tx,
                                   const NewEmailVerificationData& data) = 0;

  virtual std::optional<EmailVerification> FindActiveByUserId(
      std::string_view user_id, std::chrono::system_clock::time_point now,
      std::size_t max_attempts) = 0;

  [[nodiscard]] virtual bool MarkUsed(
      DbTransaction& tx, std::string_view verification_id,
      std::chrono::system_clock::time_point used_at,
      std::size_t max_attempts) = 0;

  virtual void MarkActiveUsedByUserId(
      DbTransaction& tx, std::string_view user_id,
      std::chrono::system_clock::time_point used_at) = 0;

  virtual void IncrementAttempts(DbTransaction& tx,
                                 std::string_view verification_id,
                                 std::chrono::system_clock::time_point now,
                                 std::size_t max_attempts) = 0;

  [[nodiscard]] virtual bool TryRecordAttempt(
      DbTransaction& tx, std::string_view email,
      const std::optional<std::string>& user_id,
      const std::optional<std::string>& ip,
      const std::optional<std::string>& user_agent,
      std::chrono::system_clock::time_point now,
      std::chrono::system_clock::time_point since,
      std::size_t max_attempts_per_email, std::size_t max_attempts_per_user,
      std::size_t max_attempts_per_ip) = 0;
};
}  // namespace smirkly::auth::services::ports
