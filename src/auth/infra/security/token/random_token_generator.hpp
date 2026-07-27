#pragma once

#include <cstddef>
#include <string>

#include <auth/services/ports/security/token_generator.hpp>

namespace smirkly::auth::infra::security {

class RandomTokenGenerator final
    : public services::ports::security::TokenGenerator {
 public:
  explicit RandomTokenGenerator(std::size_t byte_length = 32);

  [[nodiscard]] std::string Generate() override;

 private:
  std::size_t byte_length_;
};

}  // namespace smirkly::auth::infra::security
