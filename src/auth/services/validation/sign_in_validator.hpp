#pragma once

#include <optional>
#include <string>

#include <auth/services/contracts/sign_in.hpp>

namespace smirkly::auth::services::validation {
struct NormalizedSignInInput final {
  std::optional<std::string> username;
  std::optional<std::string> email;
  std::optional<std::string> phone;
  std::string rate_limit_identifier;
};

class SignInValidator final {
 public:
  [[nodiscard]] NormalizedSignInInput ValidateAndNormalize(
      const contracts::SignInCommand& cmd) const;
};
}  // namespace smirkly::auth::services::validation
