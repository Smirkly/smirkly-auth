#pragma once

#include <string>

namespace smirkly::auth::services::ports {
    class VerificationCodeGenerator {
    public:
        virtual ~VerificationCodeGenerator() = default;

        virtual std::string Generate() = 0;
    };
}
