#pragma once
#include "auth/services/auth_service.hpp"

namespace smirkly::auth::domain::services::ports {
    class VerificationCodeGenerator {
    public:
        virtual ~VerificationCodeGenerator() = default;

        virtual void send_verification_email(const domain::models::User user, std::string_view code) = 0;
    };
}
