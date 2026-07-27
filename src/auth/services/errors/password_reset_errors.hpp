#pragma once

#include <stdexcept>

namespace smirkly::auth::services::errors {

class PasswordResetError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class PasswordResetValidation final : public PasswordResetError {
 public:
  using PasswordResetError::PasswordResetError;
};

class InvalidPasswordResetToken final : public PasswordResetError {
 public:
  using PasswordResetError::PasswordResetError;
};

class PasswordResetExpired final : public PasswordResetError {
 public:
  using PasswordResetError::PasswordResetError;
};

class TooManyPasswordResetAttempts final : public PasswordResetError {
 public:
  using PasswordResetError::PasswordResetError;
};

}  // namespace smirkly::auth::services::errors
