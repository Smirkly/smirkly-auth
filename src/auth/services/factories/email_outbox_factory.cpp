#include <auth/services/factories/email_outbox_factory.hpp>

#include <utility>

namespace smirkly::auth::services::factories {
ports::EnqueueEmail EmailOutboxFactory::VerificationEmail(
    std::string to_email, std::string code, std::string correlation_id,
    std::string locale) {
  return ports::EnqueueEmail{.to_email = std::move(to_email),
                             .template_name = "verification_code",
                             .payload =
                                 {
                                     {"code", std::move(code)},
                                     {"locale", std::move(locale)},
                                 },
                             .correlation_id = std::move(correlation_id)};
}

ports::EnqueueEmail EmailOutboxFactory::PasswordResetEmail(
    std::string to_email, std::string token, std::string correlation_id,
    std::string locale) {
  return ports::EnqueueEmail{.to_email = std::move(to_email),
                             .template_name = "password_reset",
                             .payload =
                                 {
                                     {"token", std::move(token)},
                                     {"locale", std::move(locale)},
                                 },
                             .correlation_id = std::move(correlation_id)};
}
}  // namespace smirkly::auth::services::factories
