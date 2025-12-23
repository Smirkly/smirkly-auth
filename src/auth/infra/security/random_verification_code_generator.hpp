#pragma once

#include <auth/services/ports/verification_code_generator.hpp>

namespace smirkly::auth::infra::security {
    class RandomVerificationCodeGenerator : public services::ports::VerificationCodeGenerator {
    public:
        explicit RandomVerificationCodeGenerator(std::size_t lenght = 6);

        std::string Generate() override;

    private:
        std::size_t lenght_;
    };
}
