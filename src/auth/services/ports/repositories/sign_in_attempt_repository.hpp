#pragma once

#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

#include <auth/services/ports/uow/db_transaction.hpp>

namespace smirkly::auth::services::ports {
struct SignInAttemptCounters final {
  std::size_t identifier{0};
  std::size_t user{0};
  std::size_t ip{0};
};

class SignInAttemptRepository {
 public:
  virtual ~SignInAttemptRepository() = default;

  virtual SignInAttemptCounters CountRecentAttempts(
      std::string_view login_identifier,
      const std::optional<std::string>& user_id,
      const std::optional<std::string>& ip,
      std::chrono::system_clock::time_point since) = 0;

  [[nodiscard]] virtual bool TryRecordAttempt(
      DbTransaction& tx, std::string_view login_identifier,
      const std::optional<std::string>& user_id,
      const std::optional<std::string>& ip,
      const std::optional<std::string>& user_agent,
      std::chrono::system_clock::time_point now,
      std::chrono::system_clock::time_point since,
      std::size_t max_attempts_per_identifier,
      std::size_t max_attempts_per_user, std::size_t max_attempts_per_ip) = 0;
};
}  // namespace smirkly::auth::services::ports
