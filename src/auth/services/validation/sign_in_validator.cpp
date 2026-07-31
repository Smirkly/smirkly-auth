#include <auth/services/validation/sign_in_validator.hpp>

#include <cstddef>
#include <stdexcept>

#include <auth/domain/value_objects/email.hpp>
#include <auth/domain/value_objects/phone.hpp>
#include <auth/domain/value_objects/username.hpp>
#include <auth/services/errors/sign_in_errors.hpp>

namespace smirkly::auth::services::validation {
constexpr std::size_t kMaxSignInPasswordLength = 72;

NormalizedSignInInput SignInValidator::ValidateAndNormalize(
    const contracts::SignInCommand& cmd) const {
  if (!cmd.username && !cmd.email && !cmd.phone) {
    throw errors::SignInValidation("username/email/phone is required");
  }
  if (cmd.password.empty()) {
    throw errors::SignInValidation("password is required");
  }
  if (cmd.password.size() > kMaxSignInPasswordLength) {
    throw errors::SignInValidation("password is too long");
  }

  try {
    if (cmd.username) {
      auto username = domain::value_objects::Username{*cmd.username}.Value();
      return NormalizedSignInInput{
          .username = username,
          .email = std::nullopt,
          .phone = std::nullopt,
          .rate_limit_identifier = "username:" + username,
      };
    }
    if (cmd.email) {
      auto email = domain::value_objects::Email{*cmd.email}.Value();
      return NormalizedSignInInput{
          .username = std::nullopt,
          .email = email,
          .phone = std::nullopt,
          .rate_limit_identifier = "email:" + email,
      };
    }

    auto phone = domain::value_objects::Phone{*cmd.phone}.Value();
    return NormalizedSignInInput{
        .username = std::nullopt,
        .email = std::nullopt,
        .phone = phone,
        .rate_limit_identifier = "phone:" + phone,
    };
  } catch (const std::invalid_argument& e) {
    throw errors::SignInValidation(e.what());
  }
}
}  // namespace smirkly::auth::services::validation
