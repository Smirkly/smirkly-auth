#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <auth/domain/value_objects/email.hpp>
#include <auth/domain/value_objects/phone.hpp>
#include <auth/domain/value_objects/username.hpp>
#include <auth/services/contracts/sign_up.hpp>
#include <auth/services/policies/sign_up_policy.hpp>
#include <auth/services/validation/password_validator.hpp>

namespace smirkly::auth::services::validation {
struct NormalizedSignUpInput final {
  domain::value_objects::Username username;
  std::string password;
  std::optional<domain::value_objects::Email> email;
  std::optional<domain::value_objects::Phone> phone;
};

class SignUpValidator final {
 public:
  explicit SignUpValidator(policies::SignUpPolicy policy = {});

  [[nodiscard]] NormalizedSignUpInput ValidateAndNormalize(
      const contracts::SignUpCommand& cmd) const;

 private:
  policies::SignUpPolicy policy_;
  PasswordValidator password_validator_;
};
}  // namespace smirkly::auth::services::validation
