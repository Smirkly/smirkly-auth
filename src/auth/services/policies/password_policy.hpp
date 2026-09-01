#pragma once

#include <cstddef>

namespace smirkly::auth::services::policies {

struct PasswordPolicy final {
  std::size_t min_length{8};
  std::size_t max_length{72};
};

}  // namespace smirkly::auth::services::policies
