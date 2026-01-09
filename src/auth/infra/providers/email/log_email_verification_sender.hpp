#pragma once

#include <auth/domain/models/user.hpp>
#include <auth/services/ports/messaging/email_verification_sender.hpp>

namespace smirkly::auth::infra::providers::email {
    class LogEmailVerificationSender final : public services::ports::EmailVerificationSender {
    public:
        explicit LogEmailVerificationSender(
            services::ports::EmailVerificationSender &inner,
            std::string tag = "email_verification"
        );

        void SendVerificationEmail(const services::ports::VerificationEmail &msg) override;

    private:
        services::ports::EmailVerificationSender &inner_;
        std::string tag_;
    };
}
