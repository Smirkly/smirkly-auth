#pragma once

#include <cstddef>

namespace smirkly::auth::services::policies {
inline bool IsRateLimitExceeded(std::size_t count, std::size_t limit) noexcept {
  return limit > 0 && count >= limit;
}
}  // namespace smirkly::auth::services::policies
