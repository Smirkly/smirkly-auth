#pragma once

#include <auth/services/policies/password_policy.hpp>

namespace smirkly::auth::services::policies {

struct SignUpPolicy final {
  PasswordPolicy password;

  bool require_email{false};
  bool require_phone{false};
  bool require_contact{true};
};

}  // namespace smirkly::auth::services::policies
