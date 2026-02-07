#include <auth/infra/providers/email/smtp_email_verification_sender.hpp>

#include <utility>
#include <stdexcept>

#include <auth/infra/messaging/smtp_email_sender.hpp>

namespace smirkly::auth::infra::providers::email {
    SmtpEmailVerificationSender::SmtpEmailVerificationSender(
        std::unique_ptr<messaging::SmtpEmailSender> smtp_sender)
        : smtp_sender_(std::move(smtp_sender)) {
        if (!smtp_sender_) throw std::runtime_error("SmtpEmailVerificationSender: smtp_sender is null");
    }

    void SmtpEmailVerificationSender::SendVerificationEmail(const services::ports::VerificationEmail &msg) {
        const auto result = smtp_sender_->SendVerificationCode(msg.to_email, msg.code);

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
