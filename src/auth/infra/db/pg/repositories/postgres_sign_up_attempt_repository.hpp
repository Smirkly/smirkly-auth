#pragma once

#include <auth/services/ports/repositories/sign_up_attempt_repository.hpp>

namespace smirkly::auth::infra::db::pg {
namespace ports = services::ports;

class PostgresSignUpAttemptRepository final
    : public ports::SignUpAttemptRepository {
 public:
  [[nodiscard]] bool TryRecordAttempt(
      ports::DbTransaction& tx, std::string_view ip,
      std::chrono::system_clock::time_point now,
      std::chrono::system_clock::time_point since,
      std::size_t max_attempts_per_ip) override;
};

}  // namespace smirkly::auth::infra::db::pg
