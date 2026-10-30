#pragma once

#include <cstddef>

namespace smirkly::auth::services::policies {

inline constexpr std::size_t kMaxPasswordLength = 256;

struct PasswordPolicy final {
  std::size_t min_length{8};
  std::size_t max_length{kMaxPasswordLength};
};

}  // namespace smirkly::auth::services::policies
