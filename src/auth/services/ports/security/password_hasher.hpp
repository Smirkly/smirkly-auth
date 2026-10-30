#pragma once

#include <string>
#include <string_view>

namespace smirkly::auth::services::ports {
class PasswordHasher {
 public:
  virtual ~PasswordHasher() = default;

  [[nodiscard]] virtual std::string Hash(std::string_view password) const = 0;

  [[nodiscard]] virtual bool Verify(std::string_view password,
                                    std::string_view hash) const = 0;
};
}  // namespace smirkly::auth::services::ports
