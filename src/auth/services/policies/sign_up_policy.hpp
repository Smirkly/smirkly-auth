#pragma once

#include <cstddef>

namespace smirkly::auth::services::policies {

struct SignUpPolicy final {
  std::size_t password_min_len{8};
  std::size_t password_max_len{72};

  bool require_email{false};
  bool require_phone{false};
  bool require_contact{true};
};

}  // namespace smirkly::auth::services::policies
