#pragma once

#include <chrono>
#include <cstddef>
#include <string_view>

#include <auth/services/ports/uow/db_transaction.hpp>

namespace smirkly::auth::services::ports {

class SignUpAttemptRepository {
 public:
  virtual ~SignUpAttemptRepository() = default;

  [[nodiscard]] virtual bool TryRecordAttempt(
      DbTransaction& tx, std::string_view ip,
      std::chrono::system_clock::time_point now,
      std::chrono::system_clock::time_point since,
      std::size_t max_attempts_per_ip) = 0;
};

}  // namespace smirkly::auth::services::ports
