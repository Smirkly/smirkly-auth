#include <auth/infra/providers/email/log_email_verification_sender.hpp>

#include <userver/logging/log.hpp>

namespace smirkly::auth::infra::providers::email {
LogEmailVerificationSender::LogEmailVerificationSender(
    services::ports::EmailVerificationSender& inner, std::string tag)
    : inner_(inner), tag_(std::move(tag)) {}

void LogEmailVerificationSender::SendVerificationEmail(
    const services::ports::VerificationEmail& msg) {
  LOG_INFO() << tag_ << " send_verification_email"
             << " correlation_id=" << msg.correlation_id
             << " locale=" << msg.locale;

  try {
    inner_.SendVerificationEmail(msg);
    LOG_INFO() << tag_ << " send_verification_email OK"
               << " correlation_id=" << msg.correlation_id;
  } catch (const std::exception& e) {
    LOG_WARNING() << tag_ << " send_verification_email FAILED"
                  << " correlation_id=" << msg.correlation_id
                  << " error=" << e.what();
    throw;
  }
}

void LogEmailVerificationSender::SendPasswordResetEmail(
    const services::ports::PasswordResetEmail& msg) {
  LOG_INFO() << tag_ << " send_password_reset_email"
             << " correlation_id=" << msg.correlation_id
             << " locale=" << msg.locale;

  try {
    inner_.SendPasswordResetEmail(msg);
    LOG_INFO() << tag_ << " send_password_reset_email OK"
               << " correlation_id=" << msg.correlation_id;
  } catch (const std::exception& e) {
    LOG_WARNING() << tag_ << " send_password_reset_email FAILED"
                  << " correlation_id=" << msg.correlation_id
                  << " error=" << e.what();
    throw;
  }
}
}  // namespace smirkly::auth::infra::providers::email
