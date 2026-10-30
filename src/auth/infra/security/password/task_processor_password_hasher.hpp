#pragma once

#include <memory>
#include <string>
#include <string_view>

#include <userver/engine/task/task_processor_fwd.hpp>

#include <auth/services/ports/security/password_hasher.hpp>

namespace smirkly::auth::infra::security {

class TaskProcessorPasswordHasher final
    : public services::ports::PasswordHasher {
 public:
  TaskProcessorPasswordHasher(
      userver::engine::TaskProcessor& task_processor,
      std::unique_ptr<services::ports::PasswordHasher> delegate);

  [[nodiscard]] std::string Hash(std::string_view password) const override;

  [[nodiscard]] bool Verify(std::string_view password,
                            std::string_view encoded_hash) const override;

 private:
  userver::engine::TaskProcessor& task_processor_;
  std::unique_ptr<services::ports::PasswordHasher> delegate_;
};

}  // namespace smirkly::auth::infra::security
