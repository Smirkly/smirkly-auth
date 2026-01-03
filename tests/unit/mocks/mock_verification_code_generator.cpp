#include "mock_verification_code_generator.hpp"

namespace smirkly::auth::tests::mocks {
    MockVerificationCodeGenerator::MockVerificationCodeGenerator(
        std::string initial_code,
        std::size_t code_length)
        : code_(std::move(initial_code)),
          code_length_(code_length) {
    }

    std::string MockVerificationCodeGenerator::Generate() {
        ++generated_count_;
        return code_;
    }

    void MockVerificationCodeGenerator::SetNextCode(std::string code) {
        code_ = std::move(code);
    }

    std::size_t MockVerificationCodeGenerator::GetGeneratedCount() const noexcept {
        return generated_count_;
    }

    std::size_t MockVerificationCodeGenerator::GetCodeLength() const noexcept {
        return code_length_;
    }
}
