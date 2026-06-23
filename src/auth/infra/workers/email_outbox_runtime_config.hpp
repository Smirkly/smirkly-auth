#pragma once

#include <chrono>
#include <cstddef>

namespace smirkly::auth::infra::workers {

struct EmailOutboxRuntimeConfig final {
  bool processing_enabled{true};
  std::size_t batch_size{20};
  std::size_t max_attempts{10};
  std::chrono::seconds stuck_timeout{300};
  std::chrono::seconds retry_base_delay{2};
  std::chrono::seconds retry_max_delay{600};
};

}  // namespace smirkly::auth::infra::workers
