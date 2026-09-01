#pragma once

#include <auth/services/policies/verification_code_policy.hpp>
#include <auth/services/ports/support/verification_code_generator.hpp>

namespace smirkly::auth::infra::security {
class RandomVerificationCodeGenerator
    : public services::ports::VerificationCodeGenerator {
 public:
  explicit RandomVerificationCodeGenerator(
      std::size_t length = services::policies::kVerificationCodeLength);

  std::string Generate() override;

 private:
  std::size_t length_;
};
}  // namespace smirkly::auth::infra::security
