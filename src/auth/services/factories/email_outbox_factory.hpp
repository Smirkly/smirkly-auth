#pragma once

#include <string>

#include <auth/services/ports/repositories/email_outbox_repository.hpp>

namespace smirkly::auth::services::factories {
    class EmailOutboxFactory final {
    public:
        [[nodiscard]] static ports::EnqueueVerificationEmail VerificationEmail(
            std::string to_email,
            std::string code,
            std::string correlation_id,
            std::string locale
        );
    };
}
