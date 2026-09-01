#pragma once

#include <string_view>

#include <auth/services/policies/password_policy.hpp>

namespace smirkly::auth::services::validation {

class PasswordValidator final {
 public:
  explicit PasswordValidator(policies::PasswordPolicy policy = {});

  void Validate(std::string_view password) const;

 private:
  policies::PasswordPolicy policy_;
};

}  // namespace smirkly::auth::services::validation
