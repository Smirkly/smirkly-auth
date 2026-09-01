#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <auth/services/ports/uow/db_transaction.hpp>

namespace smirkly::auth::services::ports {

struct NewPasswordResetData final {
  std::string user_id;
  std::string token_hash;
  std::chrono::system_clock::time_point expires_at;
  std::optional<std::string> ip;
  std::optional<std::string> user_agent;
};

struct PasswordReset final {
  std::string id;
  std::string user_id;
  std::string token_hash;
  std::chrono::system_clock::time_point expires_at;
  std::optional<std::chrono::system_clock::time_point> used_at;
  std::int32_t attempts{0};
};

struct PasswordResetAttemptCounters final {
  std::size_t email{0};
  std::size_t user{0};
  std::size_t ip{0};
};

class PasswordResetRepository {
 public:
  virtual ~PasswordResetRepository() = default;

  virtual PasswordReset Insert(DbTransaction& tx,
                               const NewPasswordResetData& data) = 0;

  virtual std::optional<PasswordReset> FindActiveByUserId(
      std::string_view user_id, std::chrono::system_clock::time_point now,
      std::size_t max_attempts) = 0;

  virtual bool MarkUsed(DbTransaction& tx, std::string_view reset_id,
                        std::chrono::system_clock::time_point used_at,
                        std::size_t max_attempts) = 0;

  virtual void MarkActiveUsedByUserId(
      DbTransaction& tx, std::string_view user_id,
      std::chrono::system_clock::time_point used_at) = 0;

  virtual void IncrementAttempts(DbTransaction& tx, std::string_view reset_id,
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
