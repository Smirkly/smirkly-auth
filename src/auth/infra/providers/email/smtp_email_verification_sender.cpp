#include <auth/infra/providers/email/smtp_email_verification_sender.hpp>

#include <sstream>
#include <stdexcept>

namespace smirkly::auth::infra::providers::email {
    SmtpEmailVerificationSender::SmtpEmailVerificationSender(messaging::SmtpEmailSender smtp_sender)
        : smtp_sender_(std::move(smtp_sender)) {
    }

    void SmtpEmailVerificationSender::SendVerificationEmail(const services::ports::VerificationEmail &msg) {
        const auto result = smtp_sender_.SendVerificationCode(msg.to_email, msg.code);

        if (!result.ok) {
            std::ostringstream oss;
            oss << "SMTP send failed"
                    << " kind=" << static_cast<int>(result.kind)
                    << " retryable=" << (result.retryable ? 1 : 0)
                    << " error=" << result.error
                    << " correlation_id=" << msg.correlation_id;
            throw std::runtime_error(oss.str());
        }
    }
}
