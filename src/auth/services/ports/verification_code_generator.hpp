#pragma once

#include <string>

namespace smirkly::auth::domain::services::ports {
    class VerificationCodeGenerator {
    public:
        virtual ~VerificationCodeGenerator() = default;

        virtual std::string generate_email_code() = 0;
    };
}
