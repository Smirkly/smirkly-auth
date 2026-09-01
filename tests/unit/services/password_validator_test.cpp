#include <stdexcept>
#include <string>

#include <userver/utest/utest.hpp>

#include <auth/services/policies/password_policy.hpp>
#include <auth/services/validation/password_validator.hpp>

namespace {
using smirkly::auth::services::policies::PasswordPolicy;
using smirkly::auth::services::validation::PasswordValidator;

UTEST(PasswordValidator, AcceptsPasswordWithThreeCharacterClasses) {
  EXPECT_NO_THROW(PasswordValidator{}.Validate("StrongPass123"));
}

UTEST(PasswordValidator, RejectsEmptyPassword) {
  EXPECT_THROW(PasswordValidator{}.Validate(""), std::invalid_argument);
}

UTEST(PasswordValidator, RejectsPasswordBelowConfiguredMinimum) {
  const PasswordValidator validator{PasswordPolicy{.min_length = 12}};

  EXPECT_THROW(validator.Validate("Strong1!"), std::invalid_argument);
}

UTEST(PasswordValidator, RejectsPasswordAboveConfiguredMaximum) {
  const PasswordValidator validator{
      PasswordPolicy{.min_length = 8, .max_length = 12}};

  EXPECT_THROW(validator.Validate("VeryStrong123!"), std::invalid_argument);
}

UTEST(PasswordValidator, RejectsControlCharacters) {
  EXPECT_THROW(PasswordValidator{}.Validate("Strong1!\n"),
               std::invalid_argument);
}

UTEST(PasswordValidator, RejectsFewerThanThreeCharacterClasses) {
  EXPECT_THROW(PasswordValidator{}.Validate("lowercase1"),
               std::invalid_argument);
}

UTEST(PasswordValidator, RejectsInvalidLengthPolicy) {
  EXPECT_THROW(
      PasswordValidator(PasswordPolicy{.min_length = 16, .max_length = 8}),
      std::invalid_argument);
}
}  // namespace
