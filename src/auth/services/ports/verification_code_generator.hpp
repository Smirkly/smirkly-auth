#pragma once

#include <string>

namespace smirkly::auth::services::ports {
    class EmailVerificationSender {
    public:
        virtual ~VerificationCodeGenerator() = default;

        virtual std::string Generate() = 0;
    };
}
