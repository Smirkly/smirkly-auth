#include <auth/infra/providers/email/log_email_verification_sender.hpp>

#include <userver/logging/log.hpp>

namespace smirkly::auth::infra::providers::email {
    namespace {
        std::string MaskCode(std::string_view code) {
            if (code.size() <= 2) return std::string(code);
            std::string masked(code.size() - 2, '*');
            masked.append(code.substr(code.size() - 2));
            return masked;
        }
    }

    LogEmailVerificationSender::LogEmailVerificationSender(
        services::ports::EmailVerificationSender &inner,
        std::string tag
    ) : inner_(inner),
        tag_(std::move(tag)) {
    }

    void LogEmailVerificationSender::SendVerificationEmail(const services::ports::VerificationEmail &msg) {
        LOG_INFO() << tag_
               << " send_verification_email"
               << " to=" << msg.to_email
               << " correlation_id=" << msg.correlation_id
               << " locale=" << msg.locale;

        LOG_DEBUG() << tag_ << " code=" << MaskCode(msg.code);

        try {
            inner_.SendVerificationEmail(msg);
            LOG_INFO() << tag_
                       << " send_verification_email OK"
                       << " correlation_id=" << msg.correlation_id;
        } catch (const std::exception &e) {
            LOG_WARNING() << tag_
                          << " send_verification_email FAILED"
                          << " correlation_id=" << msg.correlation_id
                          << " error=" << e.what();
            throw;
        }
    }
}
