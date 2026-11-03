#pragma once

#include <string>
#include <string_view>

namespace smirkly::auth::services::ports::security {

class VerificationCodeHasher {
 public:
  virtual ~VerificationCodeHasher() = default;

  [[nodiscard]] virtual std::string Hash(std::string_view user_id,
                                         std::string_view code) const = 0;

  [[nodiscard]] virtual bool Verify(std::string_view user_id,
                                    std::string_view code,
                                    std::string_view hash) const = 0;
};

}  // namespace smirkly::auth::services::ports::security
