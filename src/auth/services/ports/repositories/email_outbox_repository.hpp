#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <auth/services/ports/uow/db_transaction.hpp>

namespace smirkly::auth::services::ports {
struct EnqueueEmail {
  std::string to_email;
  std::string template_name;
  std::unordered_map<std::string, std::string> payload;
  std::string correlation_id;
};

struct EmailOutboxEntry {
  std::string id;
  std::string lease_id;
  std::string to_email;
  std::string template_name;
  std::string payload_json;
  std::string correlation_id;
  std::int32_t attempts{0};
  std::chrono::system_clock::time_point next_attempt_at{};
};

class EmailOutboxRepository {
 public:
  virtual ~EmailOutboxRepository() = default;

  virtual void Insert(DbTransaction& tx, const EnqueueEmail& msg) = 0;

  virtual void Insert(const EnqueueEmail& msg) = 0;

  virtual std::vector<EmailOutboxEntry> ClaimBatch(
      DbTransaction& tx, std::size_t batch_size,
      std::chrono::system_clock::time_point now,
      std::chrono::seconds stuck_timeout, std::size_t max_attempts) = 0;

  [[nodiscard]] virtual bool MarkSent(DbTransaction& tx, std::string_view id,
                                      std::string_view lease_id,
                                      std::chrono::system_clock::time_point now,
                                      std::string_view last_error = {}) = 0;

  [[nodiscard]] virtual bool Reschedule(
      DbTransaction& tx, std::string_view id, std::string_view lease_id,
      std::chrono::system_clock::time_point next_at,
      std::string_view last_error) = 0;

  [[nodiscard]] virtual bool MarkDead(DbTransaction& tx, std::string_view id,
                                      std::string_view lease_id,
                                      std::chrono::system_clock::time_point now,
                                      std::string_view last_error) = 0;
};
}  // namespace smirkly::auth::services::ports
