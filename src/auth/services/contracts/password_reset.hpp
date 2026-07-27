#pragma once

#include <string>

namespace smirkly::auth::services::contracts {

struct RequestPasswordResetCommand final {
  std::string email;
};

struct ConfirmPasswordResetCommand final {
  std::string email;
  std::string token;
  std::string new_password;
};

}  // namespace smirkly::auth::services::contracts
