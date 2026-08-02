#include <auth/services/validation/password_validator.hpp>

#include <stdexcept>
#include <utility>

namespace {
bool IsLowerAscii(char c) noexcept { return c >= 'a' && c <= 'z'; }

bool IsUpperAscii(char c) noexcept { return c >= 'A' && c <= 'Z'; }

bool IsDigitAscii(char c) noexcept { return c >= '0' && c <= '9'; }

bool IsControlAscii(char c) noexcept {
  return static_cast<unsigned char>(c) < static_cast<unsigned char>(' ');
}
}  // namespace

namespace smirkly::auth::services::validation {

PasswordValidator::PasswordValidator(policies::PasswordPolicy policy)
    : policy_(std::move(policy)) {
  if (policy_.min_length == 0 || policy_.max_length < policy_.min_length) {
    throw std::invalid_argument("invalid password length policy");
  }
}

void PasswordValidator::Validate(std::string_view password) const {
  if (password.empty()) {
    throw std::invalid_argument("password is empty");
  }
  if (password.size() < policy_.min_length) {
    throw std::invalid_argument("password is too short");
  }
  if (password.size() > policy_.max_length) {
    throw std::invalid_argument("password is too long");
  }

  bool has_lower = false;
  bool has_upper = false;
  bool has_digit = false;
  bool has_other = false;

  for (const char c : password) {
    if (IsControlAscii(c) || c == '\x7f') {
      throw std::invalid_argument(
          "password must not contain control characters");
    }
    has_lower = has_lower || IsLowerAscii(c);
    has_upper = has_upper || IsUpperAscii(c);
    has_digit = has_digit || IsDigitAscii(c);
    has_other =
        has_other || (!IsLowerAscii(c) && !IsUpperAscii(c) && !IsDigitAscii(c));
  }

  const auto complexity_classes =
      static_cast<int>(has_lower) + static_cast<int>(has_upper) +
      static_cast<int>(has_digit) + static_cast<int>(has_other);
  if (complexity_classes < 3) {
    throw std::invalid_argument(
        "password must include at least three character classes");
  }
}

}  // namespace smirkly::auth::services::validation
