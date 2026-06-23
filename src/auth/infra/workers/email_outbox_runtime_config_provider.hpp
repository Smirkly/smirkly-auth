#pragma once

#include <auth/infra/workers/email_outbox_runtime_config.hpp>

namespace smirkly::auth::infra::workers {

class EmailOutboxRuntimeConfigProvider {
 public:
  virtual ~EmailOutboxRuntimeConfigProvider() = default;

  [[nodiscard]] virtual EmailOutboxRuntimeConfig Get() const = 0;
};

}  // namespace smirkly::auth::infra::workers
