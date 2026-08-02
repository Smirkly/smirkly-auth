#pragma once

#include <chrono>
#include <cstddef>

namespace smirkly::auth::services::policies {

struct SignUpRateLimitPolicy final {
  std::chrono::seconds window{std::chrono::minutes{15}};
  std::size_t max_attempts_per_ip{20};
};

}  // namespace smirkly::auth::services::policies
