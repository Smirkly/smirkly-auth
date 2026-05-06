#include <auth/services/factories/email_outbox_factory.hpp>

#include <utility>

namespace smirkly::auth::services::factories {
    ports::EnqueueVerificationEmail EmailOutboxFactory::VerificationEmail(
        std::string to_email,
        std::string code,
        std::string correlation_id,
        std::string locale
    ) {
        return ports::EnqueueVerificationEmail{
            .to_email = std::move(to_email),
            .code = std::move(code),
            .correlation_id = std::move(correlation_id),
            .locale = std::move(locale)
        };
    }
}
