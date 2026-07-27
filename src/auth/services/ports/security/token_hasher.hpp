#pragma once

#include <string>
#include <string_view>

namespace smirkly::auth::services::ports::security {
class TokenHasher {
 public:
  virtual ~TokenHasher() = default;

  [[nodiscard]] virtual std::string Hash(std::string_view token) const = 0;

  [[nodiscard]] virtual bool Verify(std::string_view token,
                                    std::string_view hash) const = 0;
};
}  // namespace smirkly::auth::services::ports::security
