#pragma once

#include <string>

namespace smirkly::auth::services::ports::security {

class TokenGenerator {
 public:
  virtual ~TokenGenerator() = default;

  [[nodiscard]] virtual std::string Generate() = 0;
};

}  // namespace smirkly::auth::services::ports::security
