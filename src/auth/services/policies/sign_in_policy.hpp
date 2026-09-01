#pragma once

#include <chrono>
#include <cstddef>

namespace smirkly::auth::services::policies {
struct SignInPolicy final {
  bool require_verified_email{true};

  std::chrono::seconds rate_limit_window{std::chrono::minutes{15}};
  std::size_t max_attempts_per_identifier{10};
  std::size_t max_attempts_per_user{10};
  std::size_t max_attempts_per_ip{50};
};
}  // namespace smirkly::auth::services::policies
