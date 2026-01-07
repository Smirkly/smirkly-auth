#pragma once

#include <auth/services/ports/support/verification_code_generator.hpp>

namespace smirkly::auth::tests::mocks {
    class MockVerificationCodeGenerator : public services::ports::VerificationCodeGenerator {
    public:
        explicit MockVerificationCodeGenerator(
            std::string initial_code = "000000",
            std::size_t code_length = 6);

        std::string Generate() override;

        void SetNextCode(std::string code);

        [[nodiscard]] std::size_t GetGeneratedCount() const noexcept;

        [[nodiscard]] std::size_t GetCodeLength() const noexcept;

    private:
        std::string code_;
        std::size_t code_length_;
        std::size_t generated_count_{0};
    };
}
