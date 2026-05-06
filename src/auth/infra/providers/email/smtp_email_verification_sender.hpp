#pragma once

#include <memory>

#include <auth/services/ports/notifications/email_verification_sender.hpp>

namespace smirkly::auth::infra::messaging {
    class SmtpEmailSender;
}

namespace smirkly::auth::infra::providers::email {
    class SmtpEmailVerificationSender final : public services::ports::EmailVerificationSender {
    public:
        explicit SmtpEmailVerificationSender(std::unique_ptr<messaging::SmtpEmailSender> smtp_sender);

        void SendVerificationEmail(const services::ports::VerificationEmail &msg) override;

    private:
        std::unique_ptr<messaging::SmtpEmailSender> smtp_sender_;
    };
}
