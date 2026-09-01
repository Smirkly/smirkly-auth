#pragma once

#include <stdexcept>
#include <string>
#include <utility>

#include <auth/domain/models/user.hpp>

namespace smirkly::auth::services::ports {
struct VerificationEmail {
  std::string to_email;
  std::string code;
  std::string correlation_id;
  std::string locale{"ru"};
};

struct PasswordResetEmail {
  std::string to_email;
  std::string token;
  std::string correlation_id;
  std::string locale{"ru"};
};

class EmailDeliveryError : public std::runtime_error {
 public:
  EmailDeliveryError(std::string message, bool retryable)
      : std::runtime_error(std::move(message)), retryable_(retryable) {}

  [[nodiscard]] bool IsRetryable() const noexcept { return retryable_; }

 private:
  bool retryable_{true};
};

class EmailVerificationSender {
 public:
  virtual ~EmailVerificationSender() = default;

  virtual void SendVerificationEmail(const VerificationEmail& msg) = 0;

  virtual void SendPasswordResetEmail(const PasswordResetEmail& msg) = 0;
};
}  // namespace smirkly::auth::services::ports
