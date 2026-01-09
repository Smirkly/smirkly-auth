#pragma once

#include <auth/infra/messaging/smtp_email_sender.hpp>
#include <auth/services/ports/messaging/email_verification_sender.hpp>

namespace smirkly::auth::infra::providers::email {
    class SmtpEmailVerificationSender final : public services::ports::EmailVerificationSender {
    public:
        explicit SmtpEmailVerificationSender(messaging::SmtpEmailSender smtp_sender);

        void SendVerificationEmail(const services::ports::VerificationEmail &msg) override;

    private:
        messaging::SmtpEmailSender smtp_sender_;
    };
}
