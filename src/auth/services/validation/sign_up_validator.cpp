#include <auth/services/validation/sign_up_validator.hpp>

#include <stdexcept>
#include <utility>

#include <auth/services/errors/sign_up_errors.hpp>

namespace smirkly::auth::services::validation {
SignUpValidator::SignUpValidator(policies::SignUpPolicy policy)
    : policy_(std::move(policy)), password_validator_(policy_.password) {}

NormalizedSignUpInput SignUpValidator::ValidateAndNormalize(
    const contracts::SignUpCommand& cmd) const {
  if (policy_.require_email && !cmd.email) {
    throw errors::SignUpValidation("email is required");
  }
  if (policy_.require_phone && !cmd.phone) {
    throw errors::SignUpValidation("phone is required");
  }
  if (policy_.require_contact && !cmd.email && !cmd.phone) {
    throw errors::SignUpValidation("email or phone is required");
  }

  try {
    password_validator_.Validate(cmd.password);

    NormalizedSignUpInput input{
        .username = domain::value_objects::Username{cmd.username},
        .password = cmd.password,
        .email = std::nullopt,
        .phone = std::nullopt,
    };

    if (cmd.email) {
      input.email = domain::value_objects::Email{*cmd.email};
    }
    if (cmd.phone) {
      input.phone = domain::value_objects::Phone{*cmd.phone};
    }

    return input;
  } catch (const std::invalid_argument& e) {
    throw errors::SignUpValidation(e.what());
  }
}
}  // namespace smirkly::auth::services::validation
